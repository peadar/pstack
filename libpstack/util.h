// Copyright (c) 2016 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#ifndef LIBPSTACK_UTIL_H
#define LIBPSTACK_UTIL_H


#include <exception>
#include <list>
#include <memory>
#include <sstream>
#include <stdio.h>
#include <string>
#include <string.h>
#include <unordered_map>

std::string dirname(const std::string &);

class Exception : public std::exception {
    mutable std::ostringstream str;
    mutable std::string intermediate;
public:
    Exception() {
    }

    Exception(const Exception &rhs) {
        str << rhs.str.str();
    }

    ~Exception() throw () {
    }

    const char *what() const throw() {
        intermediate = str.str();
        return intermediate.c_str();
    }
    std::ostream &getStream() const { return str; }
    typedef void IsStreamable;
};

template <typename E, typename Object, typename Test = typename E::IsStreamable>
inline const E &operator << (const E &stream, const Object &o) {
    stream.getStream() << o;
    return stream;
}

extern std::ostream *debug;
extern int verbose;
class Reader {
    Reader(const Reader &);
public:
    Reader() {}
    template <typename Obj> void
    readObj(off_t offset, Obj *object, size_t count = 1) const {
        if (count != 0) {
            size_t rc = read(offset, count * sizeof *object, (char *)object);
            if (rc != count * sizeof *object)
                throw Exception() << "incomplete object read from " << describe()
                   << " at offset " << offset
                   << " for " << count << " bytes";
        }
    }
    virtual size_t read(off_t off, size_t count, char *ptr) const = 0;
    virtual std::string describe() const = 0;
    virtual std::string readString(off_t offset) const;
};

class FileReader : public Reader {
    std::string name;
    int file;
    bool openfile(int &file, std::string name_);
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const;
    FileReader(std::string name, int fd = -1);
    std::string describe() const { return name; }
};


class CacheReader : public Reader {
    struct CacheEnt {
        std::string value;
        bool isNew;
        CacheEnt() : isNew(true) {}
    };
    std::shared_ptr<Reader> upstream;
    mutable std::unordered_map<off_t, CacheEnt> stringCache;
    static const size_t PAGESIZE = 1024;
    static const size_t MAXPAGES = 16;
    class Page {
        Page();
        Page(const Page &);
    public:
        off_t offset;
        size_t len;
        char data[PAGESIZE];
        Page(Reader &r, off_t offset);
    };
    mutable std::list<Page *> pages;
    Page *getPage(off_t offset) const;
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const;
    virtual std::string describe() const { return upstream->describe(); }
    CacheReader(std::shared_ptr<Reader> upstream);
    std::string readString(off_t absoff) const;
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
std::string linkResolve(std::string name);

template <typename T> T maybe(T val, T dflt) {
    return val ?  val : dflt;
}

class IOFlagSave {
    std::ios &target;
    std::ios saved;
public:
    IOFlagSave(std::ios &os)
        : target(os)
         , saved(0)
    {
        saved.copyfmt(target);
    }
    ~IOFlagSave() {
        target.copyfmt(saved);
    }
};

#endif // LIBPSTACK_UTIL_H
