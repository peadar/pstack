#include "reader.h"
#include <iostream>
#include <fcntl.h>
#include <assert.h>

FileReader::FileReader(std::string name_, int file_)
    : name(name_)
    , file(file_)
{
    if (file == -1 && (file = open(name.c_str(), O_RDONLY)) == -1)
        throw Exception() << "cannot open file " << name;
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

std::string MemReader::describe() const
{
    return "from memory image";
}

std::string
Reader:: readString(off_t offset) const
{
    char c;
    std::string res;
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
