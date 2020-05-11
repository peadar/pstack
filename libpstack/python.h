#include "libpstack/elf.h"
#include "libpstack/proc.h"
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
using python_printfunc = Elf::Addr (*)(const _object *pyo, const _typeobject *, PythonPrinter<PyV> *pc, Elf::Addr);

template <int PyV>
struct PythonPrinter {
    void print(Elf::Addr remoteAddr) const;
    struct freetype {
        void operator()(_typeobject *to) {
            free(to);
        }
    };
    mutable std::map<_typeobject *, std::unique_ptr<_typeobject, freetype>> types;

    PythonPrinter(Process &proc_, std::ostream &os_, const PstackOptions &);
    const char *prefix() const;
    void printStacks();
    Elf::Addr printThread(Elf::Addr);
    Elf::Addr printInterp(Elf::Addr);

    Process &proc;
    std::ostream &os;
    mutable std::set<Elf::Addr> visited;
    mutable int depth;
    Elf::Addr interp_head;
    Elf::Object::sptr libpython;
    Elf::Addr libpythonAddr;
    const PstackOptions &options;
    std::map<const _typeobject *, const PythonTypePrinter<PyV> *> printers;
    void findInterpreter();
    bool interpFound() const; // returns true if the printer could find the interpreter.
    void findInterpHeadFallback();
};
bool pthreadTidOffset(const Process &proc, size_t *offsetp);
