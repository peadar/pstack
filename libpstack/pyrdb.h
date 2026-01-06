#include "libpstack/proc.h"
#include <limits>
#include <vector>
#include <variant>

namespace pstack::Py {

// Forward declarations.
struct OffsetContainer;
struct RootOffsets;
struct PyTypes;
class Target;

// Declared structures named as the hidden internal python types. We don't read
// these directly, but we have offsets in them from the _PyRuntime debug offsets
// field. (keep sorted!)
struct _gc_runtime_state;
struct _gil_runtime_state;
struct PyBytesObject;
struct PyCodeObject;
struct _PyCFrame;
struct _PyInterpreterFrame;
struct PyInterpreterState;
struct PyObject;
struct _PyRuntimeState;
using _PyStackRef = uintptr_t;
struct _PyStackChunk;
struct PyThreadState;
struct PyTypeObject;
struct PyHeapTypeObject;
struct PyUnicodeObject;
struct PyTupleObject;
struct PyListObject;
struct PyLongObject;
struct PyNoneType;
struct PyDictObject;
struct PyDictKeysObject;
struct PyDictValues;
struct PyMemberDescrObject;

union _Py_CODEUNIT;

// These are for the parsed form of the JSON.
struct Structure;
using Field = std::variant< int, std::unique_ptr<Structure>, JsonNull>;
struct Structure {
    std::map<std::string, Field, std::less<>> fields;
    Structure *substructure(const std::string_view key) const {
        if ( auto fieldi = fields.find(key); fieldi != fields.end()) {
            if (auto structure = std::get_if<std::unique_ptr<Structure>>(&fieldi->second))
                return structure->get();
        }
        return nullptr;
    }
    std::optional<int> fieldOffset(const std::string_view key) const {
        if (auto it = fields.find(key); it != fields.end()) {
            if (auto off = std::get_if<int>(&it->second); off) {
                return *off;
            } else if (auto s = std::get_if<std::unique_ptr<Structure>>(&it->second); s) {
                return {(*s)->fieldOffset("<offset>")};
            }
        }
        return std::nullopt;
    }
};


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
    auto operator <=> (const Remote<T> &rhs) const = default;
    operator bool() const { return bool(remote); }

    template <typename To>
    Remote<To> reinterpretCast() const { return { reinterpret_cast<To>(remote) }; }
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
    std::vector<std::string_view> debugPath;
    static constexpr uint64_t notFound = std::numeric_limits<uint64_t>::max();
    uint64_t off{notFound};
    // Whether this offset was supplied by the interpreter's debug protocol or
    // by the DWARF-derived JSON.  Several CPython releases use different
    // names for equivalent fields, so callers must not use a default offset
    // as though it described the target's layout.
    bool found() const { return off != notFound; }
    RawOffset(OffsetContainer *container, std::string_view name_, std::initializer_list<std::string_view> debugPath, uint64_t default_off = notFound);
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
    const char *typeName{};
    const char *debugOffsetsField{};
    std::map<std::string_view, RawOffset *> fields;
    void populate(const Structure *type, const Structure *debugOffsets, const Reader::csptr &, uintptr_t object);
    OffsetContainer(const char *typeName, const char *debugOffsetsField) : typeName(typeName), debugOffsetsField(debugOffsetsField){}
    OffsetContainer() = delete;
};


class Target {
public:
    Procman::Process &proc;
private:
    Remote<_PyRuntimeState *> pyRuntime;
    std::unique_ptr<RootOffsets> offsets;
    std::unique_ptr<PyTypes> types;
    void dumpBacktrace(std::ostream &os) const;
    Remote<PyTypeObject *> pyType(Remote<PyObject *>) const;
    std::string typeName(Remote<PyTypeObject *>) const;
    template<typename To> Remote<To *> cast(const PyType<To> &to, Remote<PyObject *> from) const;

    template <typename T> Remote<T *>::PointedTo fetch(Remote<T *> remote) const {
        return proc.io->readObj<typename Remote<T *>::PointedTo>(reinterpret_cast<uintptr_t>(remote.remote));
    }
    template <typename T> std::vector<typename Remote<T *>::PointedTo> fetchArray(Remote<T *> remote, size_t sz) const {
        std::vector<typename Remote<T *>::PointedTo> v(sz);
        proc.io->readObj<typename Remote<T *>::PointedTo>(reinterpret_cast<uintptr_t>(remote.remote), v.data(), v.size());
        return v;
    }

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

public:

    template <typename T> struct DumpStream {
        const Target &target;
        const T &object;
        DumpStream(const Target &target, const T &object) : target(target), object(object) {}
    };

    Target(Procman::Process & proc_);
    std::vector<Remote<PyInterpreterState *>> interpreters() const;
    std::vector<Remote<PyThreadState *>> threads(Remote<PyInterpreterState *>) const;
    // Helper to walk dict entries and call visitor for each key/value pair
    template<typename Visitor>
    void walkDictEntries(Remote<PyDictKeysObject *> keys_remote, Remote<PyDictValues *> values, Visitor visitor) const;
    // Helper to dump dict contents given keys and values
    void dumpKeyValues(std::ostream &os, Remote<PyDictKeysObject *> keys_remote, Remote<PyDictValues *> values) const;
    // Helper to dump slots from a type's tp_dict
    void dumpSlots(std::ostream &os, Remote<PyTypeObject *> type, const Remote<PyObject *> &obj) const;


    void dump(std::ostream &os, const Remote<PyObject *> &remote) const;
    void dump(std::ostream &os, const Remote<PyBytesObject *> &remote) const;
    void dump(std::ostream &os, const Remote<PyListObject *> &remote) const;
    void dump(std::ostream &os, const Remote<PyTupleObject *> &remote) const;
    void dump(std::ostream &os, const Remote<char *> &remote) const;
    void dump(std::ostream &os, const Remote<PyUnicodeObject *> &remote) const;
    void dump(std::ostream &os, const Remote<PyLongObject *> &remote) const;
    void dump(std::ostream &os, const Remote<PyDictObject *> &remote) const;
    void dumpUserDefined(std::ostream &os, const Remote<PyObject *> &remote) const;
    template <typename T> DumpStream<T> str(const T &t) const { return DumpStream (*this, t); }
    ~Target();
};

template <typename T> std::ostream & operator << (std::ostream &os, const Target::DumpStream<T> &t) { t.target.dump(os, t.object); return os; }

template<typename To> Remote<To *> Target::cast(const PyType<To> &to, Remote<PyObject *> from) const {
    if (pyType(from) == to.typeObject)
        return { reinterpret_cast<To *>(from.remote) };
    return {0};
}

}
