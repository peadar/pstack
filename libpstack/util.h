// Copyright (c) 2016 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#ifndef LIBPSTACK_UTIL_H
#define LIBPSTACK_UTIL_H

#include <exception>
#include <limits>
#include <vector>
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

template <typename T> void stringifyImpl(std::ostringstream &os, const T&obj)
{
    os << obj;
}


template <typename T> std::string stringify(const T&obj)
{
    std::ostringstream os;
    stringifyImpl(os, obj);
    return os.str();
}

template <typename T, typename... More> void stringifyImpl(std::ostringstream &os, const T&obj, More... more)
{
    os << obj;
    stringifyImpl(os, more...);
}


template <typename T, typename... More> std::string stringify(const T&obj, More... more)
{
    std::ostringstream stream;
    stringifyImpl(stream, obj, more...);
    return stream.str();
}

extern std::ostream *debug;

extern int verbose;
class Reader {
    Reader(const Reader &);
public:
    Reader() {}
    template <typename Obj> void readObj(off_t offset, Obj *object, size_t count = 1) const;
    virtual size_t read(off_t off, size_t count, char *ptr) const = 0;
    virtual void describe(std::ostream &os) const = 0;
    virtual std::string readString(off_t offset) const;
    virtual off_t size() const = 0;
};

static inline std::ostream &operator << (std::ostream &os, const Reader &reader)
{
    reader.describe(os);
    return os;
}

template <typename Obj> void
Reader::readObj(off_t offset, Obj *object, size_t count) const
{
    if (count == 0)
        return;
    size_t rc = read(offset, count * sizeof *object, (char *)object);
    if (rc != count * sizeof *object)
        throw Exception() << "incomplete object read from " << *this
           << " at offset " << offset
           << " for " << count << " bytes";
}

class FileReader : public Reader {
    std::string name;
    int file;
    mutable off_t fileSize;
    bool openfile(int &file, std::string name_);
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const override ;
    FileReader(const std::string &name);
    ~FileReader();
    void describe(std::ostream &os) const  override { os << name; }
    off_t size() const override;
};

class CacheReader : public Reader {
    struct CacheEnt {
        std::string value;
        bool isNew;
        CacheEnt() : isNew(true) {}
    };
    std::shared_ptr<Reader> upstream;
    mutable std::unordered_map<off_t, CacheEnt> stringCache;
    static const size_t PAGESIZE = 4096;
    static const size_t MAXPAGES = 16;
    class Page {
        Page(const Page &) = delete;
    public:
        off_t offset;
        size_t len;
        char data[PAGESIZE];
        Page() {};
        void load(Reader &r, off_t offset);
    };
    mutable std::list<Page *> pages;
    Page *getPage(off_t offset) const;
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const override;
    virtual void describe(std::ostream &os) const override {
        // this must be the same as the underlying stream: we sometimes rely on the
        // FileReader's filename
        os << *upstream;
    }
    CacheReader(std::shared_ptr<Reader> upstream);
    std::string readString(off_t absoff) const override;
    ~CacheReader();
    off_t size() const override { return upstream->size(); }
};

class MemReader : public Reader {
protected:
    size_t len;
    const char *data;
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const override;
    MemReader(size_t, const char *);
    void describe(std::ostream &) const override;
    off_t size() const override { return len; }
};

class AllocMemReader : public MemReader {
   AllocMemReader(const AllocMemReader &) = delete;
   AllocMemReader() = delete;
public:
   AllocMemReader(size_t s, char *buf_) : MemReader(s, buf_) {}
   ~AllocMemReader() { delete[] data; }
};


class NullReader : public Reader {
public:
    virtual size_t read(off_t, size_t, char *) const override {
        throw Exception() << " read from null reader";
    }
    void describe(std::ostream &os) const override {
        os << "empty reader";
    }
    off_t size() const override { return 0; }
};

class OffsetReader : public Reader {
    std::shared_ptr<Reader> upstream;
    off_t offset;
    off_t length;
public:
    std::string readString(off_t absoff) const override {
        return upstream->readString(absoff + offset);
    }
    virtual size_t read(off_t off, size_t count, char *ptr) const override {
        if (off > length)
           throw Exception() << "read past end of object " << *this;
        if (off + off_t(count) > length)
           count = length - off;
        return upstream->read(off + offset, count, ptr);
    }
    OffsetReader(std::shared_ptr<Reader> upstream_, off_t offset_, off_t length_)
        : upstream(upstream_), offset(offset_), length(length_) {}
    void describe(std::ostream &os) const override {
        os << *upstream << "[" << offset << "," << offset + length << "]";
    }
    off_t size() const override { return length; }
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
std::shared_ptr<Reader> loadFile(const std::string &path);

#endif // LIBPSTACK_UTIL_H
