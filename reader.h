#include <string.h>
#include <list>
#include <string>
#include <stdio.h>

#include "ex.h"
class Reader {
public:
    template <typename Obj> void
    readObj(off_t offset, Obj *object, size_t count = 1) const {
        if (count != 0) {
            size_t rc = read(offset, count * sizeof *object, (char *)object);
            if (rc != count * sizeof *object)
                throw Exception() << "incomplete object read from " << describe();
        }
    }
    virtual size_t read(off_t off, size_t count, char *ptr) const = 0;
    virtual std::string describe() const = 0;
    std::string readString(off_t offset) const;
};

class FileReader : public Reader {
    std::string name;
    int file;
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const;
    FileReader(std::string name, int fd = -1);
    std::string describe() const { return name; }
};

class CacheReader : public Reader {
    Reader &upstream;
    static const size_t PAGESIZE = 4096;
    static const size_t MAXPAGES = 64;
    struct Page {
        off_t offset;
        size_t len;
        char data[PAGESIZE];
        Page(Reader &r, off_t offset);
    };
    mutable std::list<Page *> pages;
    size_t pagecount;
    Page *getPage(off_t offset) const;
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const;
    virtual std::string describe() const { return upstream.describe(); }
    CacheReader(Reader &upstream);
    ~CacheReader();
};

class MemReader : public Reader {
    char *data;
    size_t len;
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const;
    MemReader(char *, size_t);
    std::string describe() const;
};