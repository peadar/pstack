#include "libpstack/pyrdb.h"
#include <charconv>
#include <fstream>
#include <string_view>

namespace pstack::Py {
struct Header {
    char cookie[8];
    static std::string_view expectedCookie;
    uint64_t version;
    auto operator <=> (const Header &rhs) const = default;
};
std::string_view Header::expectedCookie { "xdebugpy" };

struct PyInterpreterState;
struct PyThreadState;
struct PyObject;
struct _PyInterpreterFrame;
struct _PyStackRef;
struct DebugFieldContainer;

struct AbstractDebugField {
    virtual void parse(std::istream &is, const Reader::csptr &) = 0;
    AbstractDebugField(DebugFieldContainer *container, std::string_view name_);
};

struct AbstractOffset : public AbstractDebugField {
    uint64_t off{0xbaadf00d};
    void parse(std::istream &is, const Reader::csptr &io) override {
        auto fieldOff = parseInt<size_t>(is);
        io->readObj(fieldOff, &off);
        std::clog << "read offset " << off << " at offset " << fieldOff << "\n";
    }
    AbstractOffset(DebugFieldContainer *container, std::string_view name_);
};

template <typename Datum> struct Offset : AbstractOffset {
    Datum value(const Reader::csptr &io) {
        return io->readObj<Datum>(off);
    }

    using AbstractOffset::AbstractOffset;
};

struct DebugFieldContainer {
    std::map<std::string_view, AbstractDebugField *> fields;
    void parseField(std::istream &is, Reader::csptr, std::string_view fieldName);
    void parse(std::istream &is, const Reader::csptr &);
};

AbstractDebugField::AbstractDebugField(DebugFieldContainer *container_, std::string_view name_)
{
    container_->fields[name_] = this;
}

AbstractOffset::AbstractOffset(DebugFieldContainer *container_, std::string_view name_)
        : AbstractDebugField{container_, name_}
{
}

void
DebugFieldContainer::parseField(std::istream &is, Reader::csptr reader, std::string_view fieldName) {
    auto fieldi = fields.find(fieldName);
    if (fieldi != fields.end()) {
        fieldi->second->parse(is, reader);
        fields.erase(fieldi);
    } else {
        std::cerr << "unsupported/duplicate field " << fieldName << "\n";
        skip<uintptr_t>(is);
    }
}

void
DebugFieldContainer::parse(std::istream &is, const Reader::csptr &reader) {
    parseObject(is, [&](std::istream &is, std::string_view field) {
        parseField(is, reader, field);
    });
    for (auto &[name, value] : fields) {
        std::cerr << "field " << name << " not found\n";
    }
}

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

struct RuntimeStateOffsets : DebugFieldContainer {
    Offset<size_t> size;
    Offset<PyThreadState *> finalizing;
    Offset<PyInterpreterState *> interpreters_head;
    RuntimeStateOffsets() 
       : size(this, "size")
        , finalizing(this, "finalizing")
        , interpreters_head(this, "interpreters_head")
    {}
};

struct InterpreterStateOffsets : DebugFieldContainer {
    Offset<PyInterpreterState*> next;
    Offset<PyThreadState*> threads_head;
    Offset<PyThreadState*> threads_main;
    Offset<PyObject *> sysdict;
    InterpreterStateOffsets()
    : next(this, "next")
        , threads_head(this, "threads_head")
        , threads_main(this, "threads_main")
        , sysdict(this, "sysdict")
    {}
};

struct ThreadStateOffsets : DebugFieldContainer {
    Offset<size_t> size;
    Offset<PyThreadState *> prev;
    Offset<PyThreadState *> next;
    Offset<PyInterpreterState *> interp;
    Offset<_PyInterpreterFrame *> current_frame;
    ThreadStateOffsets()
    :size(this, "size")
        , prev(this, "prev")
        , next(this, "next")
        , interp(this, "interp")
        , current_frame(this, "current_frame")
    {}
};


struct RootOffsets : DebugFieldContainer {
    Offset<uint64_t> version;
    Offset<size_t> free_threaded;
    SubFields<RuntimeStateOffsets> runtime_state;
    SubFields<InterpreterStateOffsets> interpreter_state;
    SubFields<ThreadStateOffsets> thread_state;
    RootOffsets(uint64_t version, Reader::csptr io);
};

RootOffsets::RootOffsets(uint64_t versionExpected, Reader::csptr io)
    : version(this, "version")
    , free_threaded(this, "free_threaded")
    , runtime_state(this, "runtime_state")
    , interpreter_state(this, "interpreter_state")
    , thread_state(this, "thread_state")
{
    std::array<char, 16> chars;
    auto [ end, ec ] = std::to_chars(chars.begin(), chars.end(), versionExpected, 16);
    std::string name = std::string(chars.begin(), end) + ".pydbg";
    std::cout << "reading offsets from " << name << "\n";
    std::ifstream in(name);
    parse(in, io);
    assert(version.off == versionExpected);
}

Remote::Remote(Procman::Process &proc_) : proc{proc_} {
    // First find a python interpreter. The first thing with the right section will do.
    pstack::Context &ctx = proc.context;

    for (auto &[addr, mapped] : proc.objects) {
        auto &sec = mapped.object(ctx)->getSection(".PyRuntime", SHT_PROGBITS);
        if (sec)
            continue;
        auto io = sec.io();
        auto h = io->readObj<Header>(0);

        debugOffsetsAddr = addr + sec.shdr.sh_addr;
        *ctx.debug << "found python runtime in " << mapped.name() << "\n";

        auto proch = proc.io->readObj<Header>(debugOffsetsAddr);
        if (proch != h) {
            *ctx.debug << "note - in memory offsets != on-disk offsets\n";
        }
        auto pyruntime = proc.io->view("debug offsets", debugOffsetsAddr);
        auto offsets = RootOffsets(proch.version, pyruntime);

        std::cout << "version from offsets is " << offsets.version.off << "\n";
        std::cout << "interpreters_head is " << offsets.runtime_state.subs.interpreters_head.value(pyruntime) << "\n";

    }

} }
