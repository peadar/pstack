#include "libpstack/proc.h"
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <variant>

namespace pstack::Py {

class Version {
public:
    inline std::string offsetFileName();
    Version(unsigned long data, Elf::Half machine) : data(data), machine(machine) {}
    Version() = delete;
    operator bool() const { return data != 0; }
    auto operator <=> (const Version &rhs) const  { return data <=> rhs.data; }
private:
    unsigned long data;
    Elf::Half machine;
    friend std::string to_string(Version pv);
};

inline std::string to_string(Version pv) {
    char phase = ((pv.data & 0xf0) >> 4) + 'a' - 0xa;
    return
        std::to_string((pv.data >> 24) & 0xff ) + "." +
        std::to_string((pv.data >> 16) & 0xff ) + "." +
        std::to_string((pv.data >> 8) & 0xff ) + phase +
        "-" + 
        (pv.machine == EM_386 ? "i386" : pv.machine == EM_X86_64 ? "x86_64" : pv.machine == EM_AARCH64 ? "aarch64" : "unknown");
}

std::string Version::offsetFileName()
{
    return "pyoff-" + to_string(*this) + ".json";
}


// Forward declarations.
struct OffsetContainer;
struct RootOffsets;
struct PyTypes;
class Target;
template <typename T> struct Remote;

class ReprStreamBuf : public std::streambuf {
    std::streambuf *destination;
    size_t *current_{};
    size_t *limit_{};
    std::set<uintptr_t> rendering_;
protected:
    std::streamsize xsputn(const char *s, std::streamsize n) override {
        auto count = std::min<size_t>(*limit_ - *current_, n);
        auto written = destination->sputn(s, count);
        *current_ += written;
        return written;
    }
    int overflow(int c) override {
        if (!current_ || *current_ == *limit_ || c == EOF)
            return EOF;
        if (destination->sputc(c) == EOF)
            return EOF;
        ++*current_;
        return c;
    }
public:
    ReprStreamBuf(std::streambuf *destination) : destination(destination) {}
    size_t *current() const { return current_; }
    size_t *limit() const { return limit_; }
    void setBudget(size_t *current, size_t *limit) { current_ = current; limit_ = limit; }
    bool begin(uintptr_t object) { return rendering_.insert(object).second; }
    void end(uintptr_t object) { rendering_.erase(object); }
};

class ReprStream : public std::ostream {
    ReprStreamBuf &buffer_;
    size_t current_{};
    size_t limit_;
    ReprStream *parent_;
    ReprStream(ReprStream &parent, size_t reserve)
        : std::ostream(&parent.buffer_)
        , buffer_(parent.buffer_)
        , limit_(parent.remaining() > reserve ? parent.remaining() - reserve : 0)
        , parent_(&parent) { buffer_.setBudget(&current_, &limit_); }
public:
    ReprStream(ReprStreamBuf &buffer, size_t limit) : std::ostream(&buffer), buffer_(buffer), limit_(limit), parent_(nullptr) { buffer_.setBudget(&current_, &limit_); }
    ReprStream(const ReprStream &) = delete;
    ~ReprStream() {
        if (parent_) {
            buffer_.setBudget(&parent_->current_, &parent_->limit_);
            parent_->current_ += current_;
        } else {
            buffer_.setBudget(nullptr, nullptr);
        }
    }
    size_t remaining() const { return limit_ - current_; }
    ReprStreamBuf &buffer() const { return buffer_; }
    ReprStream sub(size_t reserve) { return ReprStream(*this, reserve); }
};


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
    void dumpAllInterpreters(std::ostream &os, size_t indent = 0) const;
    operator bool() const { return bool( version ); }
    Elf::Object::sptr pyObj;
    Elf::Addr pyAddr;
private:
    std::ifstream findOffsetsFile(Version) const;
    Version version{0, 0};
    void dumpInterpreter(std::ostream &os, Remote<PyInterpreterState *> interp, size_t indent = 0) const;
    void dumpThread(std::ostream &os, Remote<PyThreadState *> thread, size_t indent = 0) const;
    void dumpFrame(std::ostream &os, Remote<_PyInterpreterFrame *> frame, size_t indent = 0) const;
    Remote<_PyRuntimeState *> pyRuntime;
    std::unique_ptr<RootOffsets> offsets;
    std::unique_ptr<PyTypes> types;
    Remote<PyTypeObject *> pyType(Remote<PyObject *>) const;
    std::string typeName(Remote<PyTypeObject *>) const;
    std::pair<std::string, bool> readUnicodeText(Remote<PyUnicodeObject *>, size_t maxbytes) const;
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

    template <typename T> struct ReprValueStream {
        const Target &target;
        const T &object;
        size_t maxsize;
        ReprValueStream(const Target &target, const T &object, size_t maxsize) : target(target), object(object), maxsize(maxsize) {}
    };

    Target(Procman::Process & proc_);
    std::vector<Remote<PyInterpreterState *>> interpreters() const;
    std::vector<Remote<PyThreadState *>> threads(Remote<PyInterpreterState *>) const;
    // Helper to walk dict entries and call visitor for each key/value pair
    template<typename Visitor>
    void walkDictEntries(Remote<PyDictKeysObject *> keys_remote, Remote<PyDictValues *> values, Visitor visitor) const;
    // Helper to dump dict contents given keys and values
    void dumpKeyValues(ReprStream &os, Remote<PyDictKeysObject *> keys_remote, Remote<PyDictValues *> values) const;
    // Helper to dump slots from a type's tp_dict
    void dumpSlots(ReprStream &os, Remote<PyTypeObject *> type, const Remote<PyObject *> &obj) const;

    void repr(ReprStream &os, const Remote<PyObject *> &remote) const;
    void repr(ReprStream &os, const Remote<PyBytesObject *> &remote) const;
    void repr(ReprStream &os, const Remote<PyListObject *> &remote) const;
    void repr(ReprStream &os, const Remote<PyTupleObject *> &remote) const;
    void repr(ReprStream &os, const Remote<char *> &remote) const;
    void repr(ReprStream &os, const Remote<PyUnicodeObject *> &remote) const;
    void repr(ReprStream &os, const Remote<PyLongObject *> &remote) const;
    void repr(ReprStream &os, const Remote<PyDictObject *> &remote) const;
    void reprUserDefined(ReprStream &os, const Remote<PyObject *> &remote) const;

    // Render a Python value in a repr-like form.  maxsize includes the
    // trailing ellipsis when truncation is necessary.
    template <typename T> void repr(std::ostream &os, const T &t, size_t maxsize = 80) const {
        ReprStreamBuf buffer(os.rdbuf());
        ReprStream limited(buffer, maxsize);
        repr(limited, t);
    }
    template <typename T> ReprValueStream<T> repr(const T &t, size_t maxsize = 80) const { return ReprValueStream (*this, t, maxsize); }
    ~Target();
};

template <typename T> std::ostream & operator << (std::ostream &os, const Target::ReprValueStream<T> &t) { t.target.repr(os, t.object, t.maxsize); return os; }

template<typename To> Remote<To *> Target::cast(const PyType<To> &to, Remote<PyObject *> from) const {
    if (pyType(from) == to.typeObject)
        return { reinterpret_cast<To *>(from.remote) };
    return {0};
}

}
