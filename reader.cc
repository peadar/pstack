#include <libpstack/util.h>
#include <unistd.h>
#include <stdint.h>
#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>

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
            name = lastSlash == string::npos ? string(buf) : name.substr(0, lastSlash + 1) + string(buf);
        } else {
            name = buf;
        }
    }
    return name;
}

off_t
FileReader::size() const
{
    struct stat buf;
    int rc = fstat(file, &buf);
    if (rc == -1)
        throw Exception() << "fstat failed: can't find size of file: " << strerror(errno);
    return buf.st_size;
}


bool
FileReader::openfile(int &file, std::string name_)
{
    auto fd = open(name_.c_str(), O_RDONLY);
    if (fd != -1) {
        file = fd;
        name = name_;
        return true;
    }
    return false;
}

FileReader::FileReader(const string &name_)
    : name(name_)
    , file(-1)
{
    if (!openfile(file, name_))
        throw Exception() << "cannot open file '" << name_ << "': " << strerror(errno);
}

FileReader::~FileReader()
{
    ::close(file);
}

MemReader::MemReader(size_t len_, char *data_)
    : len(len_)
    , data(data_)
{
}

size_t
MemReader::read(off_t off, size_t count, char *ptr) const
{
    if (off > off_t(len))
        throw Exception() << "read past end of memory";
    size_t rc = std::min(count, len - size_t(off));
    memcpy(ptr, data + off, rc);
    return rc;
}

void
MemReader::describe(std::ostream &os) const
{
    os << "in-memory image";
}

std::string
Reader::readString(off_t offset) const
{
    char c;
    string res;
    for (size_t s = size(); offset < s; ++offset) {
        read(offset, 1, &c);
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
        throw Exception()
            << "read " << count
            << " at " << off
            << " on " << *this
            << " failed: " << strerror(errno);
    return rc;
}

CacheReader::Page::Page(Reader &r, off_t offset_)
    : offset(offset_)
{
    try {
        len = r.read(offset_, PAGESIZE, data);
    }
    catch (std::exception &ex) {
        len = 0;
    }
    assert(offset_ % PAGESIZE == 0);
}

CacheReader::CacheReader(std::shared_ptr<Reader> upstream_)
    : upstream(upstream_)
{
}

CacheReader::~CacheReader()
{
    for (auto i = pages.begin(); i != pages.end(); ++i)
        delete *i;
}

CacheReader::Page *
CacheReader::getPage(off_t pageoff) const
{
    Page *p;
    int first = true;
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
    p = new Page(*upstream, pageoff);
    if (pages.size() == MAXPAGES) {
        delete pages.back();
        pages.pop_back();
    }
    pages.push_front(p);
    return p;
}

size_t
CacheReader::read(off_t absoff, size_t count, char *ptr) const
{
    off_t startoff = absoff;
    for (;;) {
        if (count == 0)
            break;
        size_t offsetOfDataInPage = absoff % PAGESIZE;
        off_t offsetOfPageInFile = absoff - offsetOfDataInPage;
        Page *page = getPage(offsetOfPageInFile);
        if (page == 0)
            break;
        size_t chunk = std::min(page->len - offsetOfDataInPage, count);
        memcpy(ptr, page->data + offsetOfDataInPage, chunk);
        absoff += chunk;
        count -= chunk;
        ptr += chunk;
        if (page->len != PAGESIZE)
            break;
    }
    return absoff - startoff;
}

string
CacheReader::readString(off_t offset) const
{
    auto &entry = stringCache[offset];
    if (entry.isNew) {
        entry.value = Reader::readString(offset);
        entry.isNew = false;
    }
    return entry.value;
}

std::shared_ptr<Reader>
loadFile(const std::string &path)
{
    return std::make_shared<CacheReader>(
        std::make_shared<FileReader>(path));
}
