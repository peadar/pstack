#ifndef LIBPSTACK_UTIL_H
#define LIBPSTACK_UTIL_H

#include <exception>
#include <cassert>
#include <limits>
#include <vector>
#include <list>
#include <memory>
#include <sstream>
#include <stdio.h>
#include <string>
#include <string.h>
#include <unordered_map>


extern std::string g_openPrefix;
std::string dirname(const std::string &);
std::string basename(const std::string &);

class Exception : public std::exception {
    mutable std::ostringstream str;
    mutable std::string intermediate;
public:
    Exception() throw() {
    }

    Exception(const Exception &rhs) throw() {
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

// Reader provides the basic random-access IO to a range of bytes.  The most
// basic reader is a FileReader, which allows you to access the content of a
// file from offset 0 through to the length of the file.
//
// You can compose readers on top of this - a FileReader can be wrapped in a
// CacheReader, so access to it is buffered.  OffsetReaders are "windows" on
// existing readers, where the offset is relative to an offset in the
// underlying reader (useful for accessing elf sections by section-relative
// offsets, for example.)
// There are also compressed readers for zlib and lzma-encoded content embedded
// in files.
//
// Example: ELF binaries can contain a ".gnu_debugdata" section, that is an
// LZMA encoded ELF image itself, that contains a symbol table section
// When accessing that symbol table, we'll read it from a stack of readers like
// this:
//
// FileReader (for ELF image)
// CacheReader (for performance)
// OffsetReader (for .gnu_debugdata section)
// LzmaReader (to decompress the .gnu_debugdata, and give the plain ELF image)
// OffsetReader (for .symtab in the nested ELF image)

class Reader {
    Reader(const Reader &);
public:
    Reader() {}
    virtual ~Reader() {}

    // Read a consecutive sequence of objects type Obj starting at Offset.
    template <typename Obj> void readObj(off_t offset, Obj *object, size_t count = 1) const;

    // Helper to read a single object.
    template <typename Obj> Obj readObj(off_t offset) const;
    // read a sequence of count bytes at offset off. May give a short return.
    virtual size_t read(off_t off, size_t count, char *ptr) const = 0;

    // describe this reader.
    virtual void describe(std::ostream &os) const = 0;

    // give the name of the file we are eventually reading
    virtual std::string filename() const = 0;

    // read a text string at an offset
    virtual std::string readString(off_t offset) const;

    virtual off_t size() const = 0;
    typedef std::shared_ptr<Reader> sptr;
    typedef std::shared_ptr<const Reader> csptr;
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

template <typename Obj> Obj
Reader::readObj(off_t offset) const
{
   Obj t;
   readObj(offset, &t);
   return t;
}

// Reader implementations
class FileReader : public Reader {
    std::string name;
    int file;
    mutable off_t fileSize;
    bool openfile(int &file, const std::string &name_);
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const override ;
    FileReader(std::string name_);
    ~FileReader();
    void describe(std::ostream &os) const  override { os << name; }
    std::string filename() const override { return name; }
    off_t size() const override;
};

class CacheReader : public Reader {
    struct CacheEnt {
        std::string value;
        bool isNew;
        CacheEnt() : isNew(true) {}
    };
    Reader::csptr upstream;
    mutable std::unordered_map<off_t, CacheEnt> stringCache;
    static const size_t PAGESIZE = 256;
    static const size_t MAXPAGES = 16;
    class Page {
        Page(const Page &) = delete;
    public:
        off_t offset;
        size_t len;
        char data[PAGESIZE];
        Page() {};
        void load(const Reader &r, off_t offset_);
    };
    mutable std::list<Page *> pages;
    Page *getPage(off_t pageoff) const;
public:
    virtual size_t read(off_t off, size_t count, char *ptr) const override;
    virtual void describe(std::ostream &os) const override {
        // this must be the same as the underlying stream: we sometimes rely on the
        // FileReader's filename
        os << *upstream;
    }
    CacheReader(Reader::csptr upstream_);
    std::string readString(off_t off) const override;
    ~CacheReader();
    off_t size() const override { return upstream->size(); }
    std::string filename() const override { return upstream->filename(); }
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
    std::string filename() const override { return "in-memory"; }
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
    std::string filename() const override { return "nowhere"; }
};

class OffsetReader : public Reader {
    Reader::csptr upstream;
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
    OffsetReader(Reader::csptr upstream_, off_t offset_,
          off_t length_ = std::numeric_limits<off_t>::max())
       : upstream(upstream_)
       , offset(offset_)
       , length(length_ == std::numeric_limits<off_t>::max() ? upstream->size() - offset : length_)
    { }
    void describe(std::ostream &os) const override {
        os << *upstream << "[" << offset << "," << offset + length << "]";
    }
    off_t size() const override { return length; }
    std::string filename() const override { return upstream->filename(); }
};

std::string linkResolve(std::string name);

template <typename T> T maybe(T val, T dflt) {
    return val ?  val : dflt;
}

// Save iostream formatting so we can restore them later.
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
Reader::csptr loadFile(const std::string &path);

// This allows a reader to provide an iterator over a sequence of objects of a
// given type. Given a reader r, we can use 
// for (const Foo &foo : ReaderArray<Foo>(r)) {
//   ...
// }
template <typename T>
struct ReaderArray {
   class iterator {
      const Reader *reader;
      off_t offset;
   public:
      T operator *();
      iterator(const Reader *reader_, off_t offset_) : reader(reader_),offset(offset_) {}
      bool operator == (const iterator &rhs) { return offset == rhs.offset && reader == rhs.reader; }
      bool operator != (const iterator &rhs) { return ! (*this == rhs); }
      void operator++() { offset += sizeof (T); }
   };
   const Reader &reader;
   typedef T value_type;
   iterator begin() const { return iterator(&reader, 0); }
   iterator end() const { return iterator(&reader, reader.size()); }
   ReaderArray(const Reader &reader_) : reader(reader_) {
      assert(reader.size() % sizeof (T) == 0);
   }
};

template <typename T> T ReaderArray<T>::iterator::operator *() {
   T t;
   reader->readObj(offset, &t);
   return t;
}


#endif // LIBPSTACK_UTIL_H
