#ifndef PSTACK_PYTHON_H
#define PSTACK_PYTHON_H

#include "libpstack/elf.h"
#include "libpstack/proc.h"

// version to hex
#define V2HEX(major, minor) ((major << 24) | (minor << 16))

struct PyInterpInfo {
    Elf::Object::sptr libpython;
    Elf::Addr libpythonAddr;
    Elf::Addr interpreterHead;
    std::string version;
    int versionHex;
};

// See PyCodeObject.co_flags in <code.h>
struct ArgFlags {
    unsigned int         :  2; // Don't care
    unsigned int varargs :  1; // If var args are used
    unsigned int kwargs  :  1; // If kwargs are used
    unsigned int         : 14; // Don't care
};

template <int PyV> struct PythonPrinter;

struct _object;
struct _typeobject;
/*
 * Because python2 and 3 have the same typenames, but those types are not
 * binary compatible, we can't create multiple instantiations of things like
 * readObj<PyType> Instead, we wrap the python types in versioned containers
 * like these, and read tose containers instead. Within pstack, all access to
 * python types is done in the scope of a tempate with an int version argument,
 * and there are separate instantiations for "2" and "3"
 */
template <int V, typename T> struct VersionedType {
    T t;
};

template <int V, typename T> void readPyObj(const Reader &r, size_t offset, T *ptr, size_t count = 1) {
    r.readObj<VersionedType<V, T>>(offset, reinterpret_cast<VersionedType<V, T> *>(ptr), count);
}

template <int V, typename T> T readPyObj(const Reader &r, off_t offset) {
    return r.readObj<VersionedType<V, T>>(offset).t;
}

template <int V> std::string readString(const Reader &r, const Elf::Addr addr);
template <int V> void printArguments(const PythonPrinter<V> *, const _object *, Elf::Addr addr);
template <int V> int getKwonlyArgCount(const _object *);

template <int V>
class PythonTypePrinter {
public:
    static char pyBytesType[];
    virtual Elf::Addr print(const PythonPrinter<V> *, const _object *, const _typeobject *, Elf::Addr addr) const = 0;
    virtual bool dupdetect() const { return true; }
    virtual const char * type() const = 0;
    PythonTypePrinter();
    ~PythonTypePrinter();
    static std::set<const PythonTypePrinter *> all;
};

template <int PyV>
struct PythonPrinter {
    void print(Elf::Addr remoteAddr) const;
    struct freetype {
        void operator()(_typeobject *to) {
            free(to);
        }
    };
    mutable std::map<const _typeobject *, std::unique_ptr<_typeobject, freetype>> types;

    PythonPrinter(Process &proc_, std::ostream &os_, const PstackOptions &, const PyInterpInfo &info_);
    const char *prefix() const;
    void printInterpreters(bool withModules);
    Elf::Addr printThread(Elf::Addr);
    Elf::Addr printInterp(Elf::Addr, bool withModules);

    Process &proc;
    std::ostream &os;
    mutable std::set<Elf::Addr> visited;
    mutable int depth;
    Elf::Addr interp_head;
    Elf::Object::sptr libpython;
    Elf::Addr libpythonAddr;
    const PstackOptions &options;
    const PyInterpInfo &info;
    std::map<const _typeobject *, const PythonTypePrinter<PyV> *> printers;
    bool interpFound() const; // returns true if the printer could find the interpreter.
};
bool pthreadTidOffset(const Process &proc, size_t *offsetp);
PyInterpInfo getPyInterpInfo(const Process &proc);
template <int PyV, typename T> ssize_t pyRefcnt(const T *t);
#endif
