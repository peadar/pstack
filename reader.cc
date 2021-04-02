#include "libpstack/util.h"

#include <sys/stat.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <unistd.h>

#include <cassert>
#include <cstdint>
#include <iostream>

using std::string;

string
linkResolve(string name)
{
    char buf[1024];
    int rc;
    for (;;) {
        rc = readlink(name.c_str(), buf, sizeof buf - 1);
        if (rc == -1)
            break;
        buf[rc] = 0;
        if (buf[0] != '/') {
            auto lastSlash = name.rfind('/');
            name = lastSlash == string::npos
               ? string(buf)
               : name.substr(0, lastSlash + 1) + string(buf);
        } else {
            name = buf;
        }
    }
    return name;
}

off_t
FileReader::size() const
{
    if (fileSize == -1) {
       struct stat buf{};
       int rc = fstat(file, &buf);
       if (rc == -1)
           throw (Exception() << "fstat failed: can't find size of file: " << strerror(errno));
       fileSize = buf.st_size;
    }
    return fileSize;
}

static int
openFileDirect(const std::string &name_)
{
    auto fd = open(name_.c_str(), O_RDONLY);
    if (verbose > 2) {
       if (fd != -1)
          *debug << "opened " << name_ << ", fd=" << fd << std::endl;
       else
          *debug << "failed to open " << name_ << ": " << strerror(errno) << std::endl;
    }
    return fd;
}

static int
openfile(const std::string &name)
{
    int fd;
    if (g_openPrefix != "") {
       int fd = openFileDirect(g_openPrefix + name);
       if (fd != -1)
          return fd;
    }
    fd = openFileDirect(name);
    if (fd != -1)
       return fd;
    throw (Exception() << "cannot open file '" << name << "': " << strerror(errno));
}

FileReader::FileReader(string name_)
    : name(std::move(name_))
    , file(openfile(name))
    , fileSize(-1)
{
}

FileReader::~FileReader()
{
    ::close(file);
}

MemReader::MemReader(const std::string &descr, size_t len_, const char *data_)
    : descr(descr)
    , len(len_)
    , data(data_)
{
}

size_t
MemReader::read(off_t off, size_t count, char *ptr) const
{
    if (off > off_t(len))
        throw (Exception() << "read past end of memory");
    size_t rc = std::min(count, len - size_t(off));
    memcpy(ptr, data + off, rc);
    return rc;
}

void
MemReader::describe(std::ostream &os) const
{
    os << descr;
}

std::string
Reader::readString(off_t offset) const
{
    string res;
    for (off_t s = size(); offset < s; ++offset) {
        char c;
        if (read(offset, 1, &c) != 1)
            break;
        if (c == 0)
            break;
        res += c;
    }
    return res;
}

size_t
FileReader::read(off_t off, size_t count, char *ptr) const
{
    auto rc = pread(file, ptr, count, off);
    if (rc == -1)
        throw (Exception()
            << "read " << count
            << " at " << off
            << " on " << *this
            << " failed: " << strerror(errno));
    if (rc == 0)
        throw (Exception()
            << "read " << count
            << " at " << off
            << " on " << *this
            << " hit unexpected EOF");
    return rc;
}

void
CacheReader::Page::load(const Reader &r, off_t offset_)
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
CacheReader::getPage(off_t pageoff) const
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
CacheReader::read(off_t off, size_t count, char *ptr) const
{
    off_t startoff = off;
    for (;;) {
        if (count == 0)
            break;
        size_t offsetOfDataInPage = off % PAGESIZE;
        off_t offsetOfPageInFile = off - offsetOfDataInPage;
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
CacheReader::readString(off_t off) const
{
    auto &entry = stringCache[off];
    if (entry.isNew) {
        entry.value = Reader::readString(off);
        entry.isNew = false;
    }
    return entry.value;
}

std::shared_ptr<const Reader>
loadFile(const std::string &path)
{
    return std::make_shared<CacheReader>(
        std::make_shared<FileReader>(path));
}

size_t
MmapReader::read(off_t off, size_t count, char *ptr) const {
   off_t size = std::min(count, len - size_t(off));
   memcpy(ptr, (char *)base + off, size);
   return count;
}

MmapReader::MmapReader(const std::string &name_)
   : name(name_)
{
   int fd = openfile(name);
   struct stat s;
   fstat(fd, &s);
   len = s.st_size;
   base = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
   close(fd);
   if (base == MAP_FAILED)
      throw (Exception() << "mmap failed" << strerror(errno));
}

std::string
MmapReader::readString(off_t offset) const {
   return std::string((char *)base + offset);
}

MmapReader::~MmapReader() {
   munmap(base, len);
}

OffsetReader::OffsetReader(Reader::csptr upstream_, off_t offset_, off_t length_)
    : upstream(upstream_)
    , offset(offset_)
{
    for (;;) {
        auto orReader = dynamic_cast<const OffsetReader *>(upstream.get());
        if (!orReader)
            break;
        if (verbose > 2)
            *debug << "optimize: collapse OR reader : "
                << upstream.get() << "->" << orReader->upstream.get() << "\n";
        offset += orReader->offset;
        upstream = orReader->upstream;
        if (length_ != std::numeric_limits<off_t>::max())
            length -= orReader->offset;
    }
    length = length_ == std::numeric_limits<off_t>::max() ? upstream->size() - offset : length_;
}

size_t
OffsetReader:: read(off_t off, size_t count, char *ptr) const {
    if (off > length)
       throw Exception() << "read past end of object " << *this;
    if (off + off_t(count) > length)
       count = length - off;
    return upstream->read(off + offset, count, ptr);
}
