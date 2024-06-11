#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <cassert>
#include <cstdint>
#include "libpstack/reader.h"
#include "libpstack/fs.h"
#include "libpstack/global.h"
#include <cstring>

namespace pstack {
using std::string;
Reader::Off
FileReader::size() const
{
    return fileSize;
}

FileReader::FileReader(string name_)
    : name(std::move(name_))
    , file(openfile(name))
{
    struct stat buf{};
    int rc = fstat(file, &buf);
    if (rc == -1)
       throw (Exception() << "fstat failed: can't find size of file: "
               << std::strerror(errno));
    fileSize = buf.st_size;
}

FileReader::~FileReader()
{
    ::close(file);
}

MemReader::MemReader(const string &descr, size_t len_, const char *data_)
    : descr(descr)
    , len(len_)
    , data(data_)
{
}

namespace {

// Clang can add checks to the likes of
// strcpy((char *)ptr + off);
// to validate that "ptr" is not a null pointer.
// In our case, for a memory reader in our own address space, we need to allow
// that, as the offset will be the raw pointer value. Use this to hide the
// [cn]astiness.
const char *ptroff(const void *base, uintptr_t off) {
    return (char *)((uintptr_t)base + off);
}
}


size_t
MemReader::read(Off off, size_t count, char *ptr) const
{
    if (off > Off(len))
        throw (Exception() << "read past end of memory");
    size_t rc = std::min(count, len - size_t(off));
    memcpy(ptr, ptroff(data, off), rc);
    return rc;
}

void
MemReader::describe(std::ostream &os) const
{
    os << descr;
}

string
MemReader::readString(Off offset) const {
   return string(ptroff(data, offset));
}


string
Reader::readString(Off offset) const
{
    if (offset == 0)
        return "(null)";
    string res;
    for (Off s = size(); offset < s; ++offset) {
        char c;
        if (read(offset, 1, &c) != 1)
            break;
        if (c == 0)
            break;
        res += c;
    }
    return res;
}

Reader::csptr
Reader::view(const std::string &name, Off offset, Off size) const {
   return std::make_shared<OffsetReader>(name, shared_from_this(), offset, size);
}

size_t
FileReader::read(Off off, size_t count, char *ptr) const
{
    auto rc = pread(file, ptr, count, off);
    if (rc == -1)
        throw (Exception()
            << "read " << count
            << " at " << (void *)off
            << " on " << *this
            << " failed: " << strerror(errno));
    return rc;
}

void
CacheReader::Page::load(const Reader &r, Off offset_)
{
    assert(offset_ % data.size() == 0);
    len = r.read(offset_, data.size(), data.data());
    offset = offset_;
}

CacheReader::CacheReader(Reader::csptr upstream_)
    : upstream(std::move(upstream_))
{
}

void
CacheReader::flush() {
    pages.clear();
}

CacheReader::Page &
CacheReader::getPage(Off pageoff) const
{
    bool first = true;
    for (auto i = pages.begin(); i != pages.end(); ++i) {
        if ((*i)->offset == pageoff) {
            // move page to front.
            if (!first) {
                auto page = std::exchange(*i, nullptr);
                pages.erase(i);
                pages.push_front(std::move(page));
            }
            return **pages.begin();
        }
        first = false;
    }

    std::unique_ptr<Page> p;
    if (pages.size() == MAXPAGES) {
        // steal the oldest page.
        p = std::exchange( pages.back(), nullptr );
        pages.pop_back();
    } else {
        p = std::make_unique<Page>();
    }
     p->load(*upstream, pageoff);
     pages.push_front(std::move(p));
     return **pages.begin();
}

size_t
CacheReader::read(Off off, size_t count, char *ptr) const
{
    if (count >= PAGESIZE)
        return upstream->read(off, count, ptr);
    Off startoff = off;
    for (;;) {
        if (count == 0)
            break;
        size_t offsetOfDataInPage = off % PAGESIZE;
        Off offsetOfPageInFile = off - offsetOfDataInPage;
        Page &page = getPage(offsetOfPageInFile);
        size_t chunk = std::min(page.len - offsetOfDataInPage, count);
        memcpy(ptr, page.data.data() + offsetOfDataInPage, chunk);
        off += chunk;
        count -= chunk;
        ptr += chunk;
        if (page.len != PAGESIZE)
            break;
    }
    return off - startoff;
}

string
CacheReader::readString(Off off) const
{
    auto [it, neu] = stringCache.insert(std::make_pair(off, std::string{}));
    if (neu)
        it->second = Reader::readString(off);
    return it->second;
}

Reader::csptr
loadFile(const string &path)
{
    return std::make_shared<CacheReader>(
        std::make_shared<FileReader>(path));
}

MmapReader::MmapReader(const string &name_)
   : MemReader(name_, 0, nullptr)
{
   int fd = openfile(name_);
   struct stat s;
   fstat(fd, &s);
   len = s.st_size;
   void *p = mmap(nullptr, len, PROT_READ, MAP_PRIVATE, fd, 0);
   close(fd);
   if (p == MAP_FAILED)
      throw (Exception() << "mmap failed: " << strerror(errno));
   data = static_cast<char *>(p);
}

MmapReader::~MmapReader() {
   munmap((void *)data, len);
}

class MemOffsetReader final : public MemReader {
   Reader::csptr upstream;
public:
   MemOffsetReader(const std::string &name, const MemReader *upstream_, Off offset, Off size)
      : MemReader(name, size, ptroff(upstream_->data, offset))
      , upstream(upstream_->shared_from_this())
   {
   }
};

MemReader::csptr
MemReader::view(const std::string &name, Off offset, Off size) const {
   return std::make_shared<MemOffsetReader>(name, this, offset, size);
}


OffsetReader::OffsetReader(std::string name_, Reader::csptr upstream_, Off offset_, Off length_)
    : upstream(upstream_)
    , offset(offset_)
    , name(std::move(name_))
{
    // If we create an offset reader with the upstream being another offset
    // reader, we can just add the offsets, and use the
    // upstream-of-the-upstream instead.
    for (;;) {
        auto orReader = dynamic_cast<const OffsetReader *>(upstream.get());
        if (!orReader)
            break;
        if (verbose > 2)
            *debug << "optimize: collapse offset reader : " << *upstream.get() << "->" << *orReader->upstream.get() << "\n";
        offset += orReader->offset;
        upstream = orReader->upstream;
    }
    length = length_ == std::numeric_limits<Off>::max() ? upstream->size() - offset : length_;
}

size_t
OffsetReader::read(Off off, size_t count, char *ptr) const {
    if (off > length)
       throw Exception() << "read past end of object " << *this;
    if (off + Off(count) > length)
       count = length - off;
    return upstream->read(off + offset, count, ptr);
}

Reader::Off
OffsetReader::size() const {
   return length;
}

std::pair<uintmax_t, size_t>
Reader::readULEB128(Off off) const
{
    ReaderArray<unsigned char> ar ( *this, off );
    return readleb128<uintmax_t>(ar.begin());
}

std::pair<intmax_t, size_t>
Reader::readSLEB128(Off off) const
{
    ReaderArray<unsigned char> ar ( *this, off );
    return readleb128<intmax_t>(ar.begin());
}


std::pair<uintmax_t, size_t>
MemReader::readULEB128(Off off) const
{
    return readleb128<uintmax_t>(ptroff(data, off));
}

std::pair<intmax_t, size_t>
MemReader::readSLEB128(Off off) const
{
    return readleb128<intmax_t>(ptroff(data, off));
}

}
