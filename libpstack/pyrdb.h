#include "libpstack/proc.h"
#include <vector>

namespace pstack::Py {

// Forward declarations.
struct OffsetContainer;

// Declared structures named as the hidden internal python types. We don't read
// these directly, but we have offsets in them from the _PyRuntime debug offsets
// field. (keep sorted!)
struct DebugFieldContainer;
struct _gc_runtime_state;
struct _gil_runtime_state;
struct PyBytesObject;
struct PyCodeObject;
struct _PyDebugOffsets;
struct _PyInterpreterFrame;
struct PyInterpreterState;
struct PyObject;
struct _PyRuntimeState;
struct _PyStackChunk;
using _PyStackRef = uintptr_t;
struct PyThreadState;
struct PyTypeObject;
struct PyUnicodeObject;
struct PyTupleObject;

union _Py_CODEUNIT;


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
    std::vector<PointedTo> fetchArray(const Reader::csptr &as, size_t len) requires std::is_pointer_v<T> {
        std::vector<PointedTo> v(len);
        as->readObj<PointedTo>(reinterpret_cast<uintptr_t>(remote), v.data(), v.size());
        return v;
    }
    auto operator <=> (const Remote<T> &rhs) const = default;
    operator bool() const { return bool(remote); }
};

template <typename To>
struct PyType {
    Remote<PyTypeObject *> typeObject;
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
    Remote<Field *> operator()(Remote<Container *> container) const {
        return { reinterpret_cast<Field *>( uintptr_t(container.remote) + off ) };
    }
    using RawOffset::RawOffset;
};

struct OffsetContainer {
    size_t size;
    std::map<std::string_view, RawOffset *> fields;
    void parse(std::istream &is, const Reader::csptr &, uintptr_t object);
};

struct RootOffsets;

struct PyTypes;

struct Target {
    Procman::Process &proc;
    Remote<_PyRuntimeState *> pyRuntime;
    std::unique_ptr<RootOffsets> offsets;
    std::unique_ptr<PyTypes> types;
    Target(Procman::Process & proc_);
    std::vector<Remote<PyInterpreterState *>> interpreters() const;
    std::vector<Remote<PyThreadState *>> threads(Remote<PyInterpreterState *>) const;
    void dumpBacktrace(std::ostream &os) const;
    Remote<PyTypeObject *> pyType(Remote<PyObject *>) const;
    std::string_view typeName(Remote<PyTypeObject *>) const;
    template<typename To> Remote<To *> cast(const PyType<To> &to, Remote<PyObject *> from) const;
    void dump(std::ostream &os, const Remote<PyObject *> &remote) const;
    void dump(std::ostream &os, const Remote<char *> &remote) const;
    void dump(std::ostream &os, const Remote<PyUnicodeObject *> &remote) const;

    // syntactic shortcut for Remote<T>::fetch
    template <typename T> Remote<T *>::PointedTo fetch(Remote<T *> remote) const { return remote.fetch(proc.io); }
    template <typename T> std::vector<typename Remote<T *>::PointedTo> fetchArray(Remote<T *> remote, size_t sz) const
    { return remote.fetchArray(proc.io, sz); }
    ~Target();


    // follows a list starting with a pointer in one object
    template <typename Container, typename Field>
    std::vector<Remote<Field *>> followList(
        const Remote<Container*> &container,
        const Offset<Container, Field *> &headField,
        const Offset<Field, Field *> &nextField) const {
        std::vector<Remote<Field *>> result;
        for (auto cur = fetch(headField(container)); cur; cur = fetch(nextField(cur)))
            result.push_back(cur);
        return result;
    }
};

template<typename To> Remote<To *> Target::cast(const PyType<To> &to, Remote<PyObject *> from) const {
    if (pyType(from) == to.typeObject)
        return { reinterpret_cast<To *>(from.remote) };
    return {0};
}

}
