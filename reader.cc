#include "reader.h"
#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <assert.h>

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
        std::clog << "resolve " << name << " to " << buf << std::endl;

        if (buf[0] != '/') {
            auto lastSlash = name.rfind('/');
            name = lastSlash == string::npos ? string(buf) : name.substr(0, lastSlash + 1) + string(buf);
        } else {
            name = buf;
        }
    }
    return name;
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

FileReader::FileReader(string name_, int file_)
    : name(name_)
    , file(file_)
{
    if (file == -1 && !openfile(file, name_))
        throw Exception() << "cannot open file '" << name_ << "': " << strerror(errno);
}

MemReader::MemReader(char *data_, size_t len_)
    : data(data_), len(len_)
{
}

size_t
MemReader::read(off_t off, size_t count, char *ptr) const
{
    size_t rc = std::min(count, len - size_t(off));
    memcpy(ptr, data + off, rc);
    return rc;
}

string
MemReader::describe() const
{
    return "from memory image";
}

string
Reader:: readString(off_t offset) const
{
    char c;
    string res;
    for (;;) {
        readObj(offset++, &c);
        if (c == 0)
            break;
        res += c;
    }
    return res;
}

size_t
FileReader::read(off_t off, size_t count, char *ptr) const
{
    if (lseek(file, off, SEEK_SET) == -1)
        throw Exception()
            << "seek to " << off
            << " on " << describe()
            << " failed: " << strerror(errno);
    ssize_t rc = ::read(file, ptr, count);
    if (rc == -1)
        throw Exception()
            << "read " << count
            << " at " << off
            << " on " << describe()
            << " failed: " << strerror(errno);
    return rc;
}

CacheReader::Page::Page(Reader &r, off_t offset_)
    : offset(offset_)
    , len(r.read(offset_, PAGESIZE, data))
{
    assert(offset_ % PAGESIZE == 0);
}

CacheReader::CacheReader(std::shared_ptr<Reader> upstream_)
    : upstream(upstream_)
{
}

CacheReader::~CacheReader()
{
    for (auto i : pages)
        delete i;
}

CacheReader::Page *
CacheReader::getPage(off_t pageoff) const
{
    Page *p;
    for (auto i = pages.begin(); i != pages.end(); ++i) {
        p = *i;
        if (p->offset == pageoff) {
            // move page to front.
            pages.erase(i);
            pages.push_front(p);
            return p;
        }
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
