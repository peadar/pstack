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

template <typename T> struct Remote;
template <typename Field>
using FromRemote = std::conditional_t<std::is_pointer_v<Field>, Remote<Field>, Field>;

template <typename T> struct Remote {
    T remote;
    using PointedTo = FromRemote<std::remove_pointer_t<T>>;
    PointedTo fetch(const Reader::csptr &as) requires std::is_pointer_v<T> {
        return as->readObj<PointedTo>(reinterpret_cast<uintptr_t>(remote));
    }
};

struct AbstractDebugField {
    virtual void parse(std::istream &is, const Reader::csptr &) = 0;
    AbstractDebugField(DebugFieldContainer *container, std::string_view name_);
};

template <typename T> inline std::ostream &operator << (std::ostream &os, const Remote<T> &rt) {
    return os << "Remote<" << rt.remote << ">";
}

struct AbstractOffset : public AbstractDebugField {
    uint64_t off{0xbaadf00d};
    void parse(std::istream &is, const Reader::csptr &io) override {
        auto fieldOff = parseInt<size_t>(is);
        io->readObj(fieldOff, &off);
    }
    AbstractOffset(DebugFieldContainer *container, std::string_view name_);
};

template <typename Container, typename Field> struct Offset : AbstractOffset {

    FromRemote<Field> value(const Reader::csptr &io, Remote<Container *> rm) {
        return io->readObj<FromRemote<Field>>(uintptr_t(rm.remote));
    }
    using AbstractOffset::AbstractOffset;
};

struct DebugFieldContainer {
    std::map<std::string_view, AbstractDebugField *> fields;
    void parseField(std::istream &is, Reader::csptr, std::string_view fieldName);
    void parse(std::istream &is, const Reader::csptr &);
};


struct SubFieldContainer : public AbstractDebugField {
    DebugFieldContainer *child;
    SubFieldContainer(DebugFieldContainer *parent, std::string_view name_, DebugFieldContainer *child_) :
    AbstractDebugField{parent, name_}, child{child_} {}
    virtual void parse(std::istream &is, const Reader::csptr &reader) {
        child->parse(is, reader);
    }
};

template <typename Subs> struct SubFields : SubFieldContainer {
    Subs subs;
    SubFields(DebugFieldContainer *parent, std::string_view name_) : SubFieldContainer(parent, name_, &subs) {}
};

struct RootOffsets;
struct Target {
    Procman::Process &proc;
    Remote<_PyRuntimeState *> pyRuntimeAddr;
    std::unique_ptr<RootOffsets> offsets;
    Target(Procman::Process & proc_);
    std::vector<Remote<PyInterpreterState *>> interpreters();
    std::vector<Remote<PyThreadState *>> threads(Remote<PyInterpreterState *>);
    ~Target();
};

}

