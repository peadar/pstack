#include "libpstack/proc.h"

namespace pstack::Py {

// Hidden internal python types.
struct PyInterpreterState;
struct PyThreadState;
struct PyObject;
struct _PyInterpreterFrame;
struct _PyStackRef;
struct _gc_runtime_state;
struct DebugFieldContainer;
struct _PyStackChunk;
struct _gil_runtime_state;
struct _PyRuntimeState;
struct _PyDebugOffsets;
struct PyCodeObject;
union _Py_CODEUNIT;

struct OffsetContainer;

// A remote object. We use this to wrap pointers in the target, so they are not dereferenceable locally.
template <typename T> struct Remote;

// An object read from the remote - for pointers, it's wrapped in Remote. For
// non-pointers, it's "raw".
template <typename Field>
using FromRemote = std::conditional_t<std::is_pointer_v<Field>, Remote<Field>, Field>;

// Simple wrapper. For pointer types, you can dereference in the remote process.
template <typename T> struct Remote {
    T remote;
    using PointedTo = FromRemote<std::remove_pointer_t<T>>;
    PointedTo fetch(const Reader::csptr &as) requires std::is_pointer_v<T> {
        return as->readObj<PointedTo>(reinterpret_cast<uintptr_t>(remote));
    }
};

template <typename T> inline std::ostream &operator << (std::ostream &os, const Remote<T> &rt) {
    return os << "Remote<" << rt.remote << ">";
}

// An offset field. This has no typing associated with it and is just an offset
// somewhere in memory, as found inthe _Py_DebugOffsets structure at the start
// of _PyRuntime - we read the offsets themselves out of the process, based on
// the offets of those offsets presented in the JSON input file for the given
// python interpreter.
//
// Eg - the JSON files has
// ```
// ... "interpreter_state": { "id" : 56 ... } ...
// ```
//
// This indicates that the "id" field of the interpreter_state object has an
// offset stored 56 bytes into the _PyRuntime section
//
struct RawOffset {
    uint64_t off{0xbaadf00d};
    void parse(std::istream &is, const Reader::csptr &io, uintptr_t object) {
        io->readObj(object + parseInt<size_t>(is), &off);
    }
    RawOffset(OffsetContainer *container, std::string_view name_);
};

// A concrete offset of a field of Container of type Field. "value()"
// essentially deferences the field of a remote pointer in a remote process to
// give the content back.
// POD objects will come back as those POD objects. Pointer types "T*" will come
// back as "Remote<T *>"
template <typename Container, typename Field> struct Offset : RawOffset {
    FromRemote<Field> value(const Reader::csptr &io, Remote<Container *> rm) {
        return io->readObj<FromRemote<Field>>(uintptr_t(rm.remote) + off);
    }
    using RawOffset::RawOffset;
};

struct OffsetContainer {
    size_t size;
    std::map<std::string_view, RawOffset *> fields;
    void parse(std::istream &is, const Reader::csptr &, uintptr_t object);
};

struct RootOffsets;
struct Target {
    Procman::Process &proc;
    Remote<_PyRuntimeState *> pyRuntimeAddr;
    std::unique_ptr<RootOffsets> offsets;
    Target(Procman::Process & proc_);
    std::vector<Remote<PyInterpreterState *>> interpreters() const;
    std::vector<Remote<PyThreadState *>> threads(Remote<PyInterpreterState *>) const;
    ~Target();
    void dumpBacktrace(std::ostream &os) const;
};

}

