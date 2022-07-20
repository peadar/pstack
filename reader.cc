#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <cassert>
#include <cstdint>
#include "libpstack/reader.h"
#include "libpstack/fs.h"
#include "libpstack/global.h"

std::vector<std::pair<std::string,std::string>> pathReplacements;

using std::string;
Reader::Off
FileReader::size() const
{
    return fileSize;
}

static int
openFileDirect(const string &name_, int mode, int mask)
{
    auto fd = open(name_.c_str(), mode, mask);
    if (verbose > 2) {
       if (fd != -1)
          *debug << "opened " << name_ << ", fd=" << fd << std::endl;
       else
          *debug << "failed to open " << name_ << ": " << strerror(errno) << std::endl;
    }
    return fd;
}

int
openfile(const string &name, int mode, int mask)
{
    int fd = -1;
    for (auto &r : pathReplacements) {
       if (name.compare(0, r.first.size(), r.first) == 0) {
          fd = openFileDirect(r.second + std::string(name, r.first.size()), mode, mask);
          if (fd != -1)
             return fd;
       }
    }
    fd = openFileDirect(name, mode, mask);
    if (fd != -1)
       return fd;
    throw (Exception() << "cannot open file '" << name << "': " << strerror(errno));
}

FileReader::FileReader(string name_)
    : name(std::move(name_))
    , file(openfile(name))
{
    struct stat buf{};
    int rc = fstat(file, &buf);
    if (rc == -1)
       throw (Exception() << "fstat failed: can't find size of file: " << strerror(errno));
    fileSize = buf.st_size;
}

FileReader::~FileReader()
{
    ::close(file);
}

MemReader::MemReader(const string &descr, size_t len_, const void *data_)
    : descr(descr)
    , len(len_)
    , data(data_)
{
}

size_t
MemReader::read(Off off, size_t count, char *ptr) const
{
    if (off > Off(len))
        throw (Exception() << "read past end of memory");
    size_t rc = std::min(count, len - size_t(off));
    memcpy(ptr, (const char *)data + off, rc);
    return rc;
}

void
MemReader::describe(std::ostream &os) const
{
    os << descr;
}

string
MemReader::readString(Off offset) const {
   return string((char *)data + offset);
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
    if (rc == 0)
        throw (Exception()
            << "read " << count
            << " at " << (void *)off
            << " on " << *this
            << " hit unexpected EOF");
    return rc;
}

void
CacheReader::Page::load(const Reader &r, Off offset_)
{
    assert(offset_ % PAGESIZE == 0);
    len = r.read(offset_, PAGESIZE, data);
    offset = offset_;
}

CacheReader::CacheReader(Reader::csptr upstream_)
    : upstream(move(upstream_))
{
}

void
CacheReader::flush() {
    std::list<Page *> clearpages;
    std::swap(pages, clearpages);
    for (auto &i : clearpages)
        delete i;
}

CacheReader::~CacheReader()
{
    flush();
}

CacheReader::Page *
CacheReader::getPage(Off pageoff) const
{
    Page *p;
    bool first = true;
    for (auto i = pages.begin(); i != pages.end(); ++i) {
        p = *i;
        if (p->offset == pageoff) {
            // move page to front.
            if (!first) {
                pages.erase(i);
                pages.push_front(p);
            }
            return p;
        }
        first = false;
    }
    if (pages.size() == MAXPAGES) {
        p = pages.back();
        pages.pop_back();
    } else {
        p = new Page();
    }
    try {
        p->load(*upstream, pageoff);
        pages.push_front(p);
        return p;
    }
    catch (...) {
        // failed to load page - delete it, and continue with error.
        delete p;
        throw;
    }

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
        Page *page = getPage(offsetOfPageInFile);
        if (page == nullptr)
            break;
        size_t chunk = std::min(page->len - offsetOfDataInPage, count);
        memcpy(ptr, page->data + offsetOfDataInPage, chunk);
        off += chunk;
        count -= chunk;
        ptr += chunk;
        if (page->len != PAGESIZE)
            break;
    }
    return off - startoff;
}

string
CacheReader::readString(Off off) const
{
    auto &entry = stringCache[off];
    if (entry.isNew) {
        entry.value = Reader::readString(off);
        entry.isNew = false;
    }
    return entry.value;
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
   data = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
   close(fd);
   if (data == MAP_FAILED)
      throw (Exception() << "mmap failed: " << strerror(errno));
}

MmapReader::~MmapReader() {
   munmap((void *)data, len);
}

class MemOffsetReader : public MemReader {
   Reader::csptr upstream;
public:
   MemOffsetReader(const std::string &name, const MemReader *upstream_, Off offset, Off size)
      : MemReader(name, size, (char *)upstream_->data + offset)
      , upstream(upstream_->shared_from_this())
   {
   }
};

MemReader::csptr
MemReader::view(const std::string &name, Off offset, Off size) const {
   return std::make_shared<MemOffsetReader>(name, this, offset, size);
}


OffsetReader::OffsetReader(const std::string& name, Reader::csptr upstream_, Off offset_, Off length_)
    : upstream(upstream_)
    , offset(offset_)
    , name(name)
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
