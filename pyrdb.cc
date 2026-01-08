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

struct RuntimeStateOffsets : DebugFieldContainer {
    template<typename Field> using Off = Offset<_PyRuntimeState, Field>;
    Off<size_t> size;
    Off<PyThreadState *> finalizing;
    Off<PyInterpreterState *> interpreters_head;
    RuntimeStateOffsets() 
       : size(this, "size")
        , finalizing(this, "finalizing")
        , interpreters_head(this, "interpreters_head")
    {}
};

struct InterpreterStateOffsets : DebugFieldContainer {
    template <typename Field> using Off = Offset<PyInterpreterState, Field>;
    Off<void*> size;
    Off<int64_t> id;
    Off<PyInterpreterState*> next;
    Off<PyThreadState*> threads_head;
    Off<PyThreadState*> threads_main;
    Off<_gc_runtime_state> gc;
    Off<PyObject *> imports_modules;
    Off<PyObject *> sysdict;
    Off<PyObject *> builtins;
    Off<_gil_runtime_state *> ceval_gil;
    Off<_gil_runtime_state> gil_runtime_state;
    Off<int> gil_runtime_state_locked;
    Off<void *> gil_runtime_state_enabled; // XXX? zero.
    Off<PyThreadState *> gil_runtime_state_holder;
    Off<uint64_t> code_object_generation;
    Off<uint64_t> tlbc_generation;
    InterpreterStateOffsets()
    : size(this, "size")
        , id(this, "id")
        , next(this, "next")
        , threads_head(this, "threads_head")
        , threads_main(this, "threads_main")
        , gc(this, "gc")
        , imports_modules(this, "imports_modules")
        , sysdict(this, "sysdict")
        , builtins(this, "builtins")
        , ceval_gil(this, "ceval_gil")
        , gil_runtime_state(this, "gil_runtime_state")
        , gil_runtime_state_locked(this, "gil_runtime_state_locked")
        , gil_runtime_state_enabled(this, "gil_runtime_state_enabled")
        , gil_runtime_state_holder(this, "gil_runtime_state_holder")
        , code_object_generation(this, "code_object_generation")
        , tlbc_generation(this, "tlbc_generation")
    {}
};

struct ThreadStateOffsets : DebugFieldContainer {
    template <typename Field> using Off = Offset<PyThreadState, Field>;
    Off<size_t> size;
    Off<PyThreadState *> prev;
    Off<PyThreadState *> next;
    Off<PyInterpreterState *> interp;
    Off<_PyInterpreterFrame *> current_frame;
    Off<unsigned long> thread_id;
    Off<unsigned long> native_thread_id;
    Off<_PyStackChunk *> datastack_chunk;
    Off<unsigned int> status;
    ThreadStateOffsets()
    :size(this, "size")
        , prev(this, "prev")
        , next(this, "next")
        , interp(this, "interp")
        , current_frame(this, "current_frame")
        , thread_id(this, "thread_id")
        , native_thread_id(this, "native_thread_id")
        , datastack_chunk(this, "datastack_chunk")
        , status(this, "status")
    {}
};


struct RootOffsets : DebugFieldContainer {
    template <typename Field> using Off = Offset<_PyDebugOffsets, Field>;
    Off<uint64_t> version;
    Off<size_t> free_threaded;
    SubFields<RuntimeStateOffsets> runtime_state;
    SubFields<InterpreterStateOffsets> interpreter_state;
    SubFields<ThreadStateOffsets> thread_state;
    RootOffsets(uint64_t version, Reader::csptr io);
    ~RootOffsets();
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

RootOffsets::~RootOffsets() {}

Target::Target(Procman::Process &proc_)
: proc{proc_}
{
    // First find a python interpreter. The first thing with the right section will do.
    pstack::Context &ctx = proc.context;

    for (auto &[addr, mapped] : proc.objects) {
        auto &sec = mapped.object(ctx)->getSection(".PyRuntime", SHT_PROGBITS);
        if (!sec)
            continue;
        auto io = sec.io();
        auto headerOnDisk = io->readObj<Header>(0);

        pyRuntimeAddr.remote = reinterpret_cast<_PyRuntimeState *>(addr + sec.shdr.sh_addr);
        Remote<Header *> remoteHeader{reinterpret_cast<Header *>(addr + sec.shdr.sh_addr)};
        Header headerInProc = remoteHeader.fetch(proc.io);

        if (headerInProc != headerOnDisk)
            *ctx.debug << "note - in memory offsets != on-disk offsets\n";
        offsets = make_unique<RootOffsets>(headerInProc.version, proc.io);
        auto &threadOffs = offsets->thread_state.subs;
        for (auto i : interpreters()) {
            for (auto t : threads(i)) {
                auto id = threadOffs.thread_id.value(proc.io, t);
                auto native_id = threadOffs.native_thread_id.value(proc.io, t);
                std::cerr << "thread id: " << id << "\n";
                std::cerr << "native id: " << native_id << "\n";
            }
        }
    }
}

std::vector<Remote<PyInterpreterState *>>
Target::interpreters() {
    std::vector<Remote<PyInterpreterState *>> interps;
    auto &runtimeOffs = offsets->runtime_state.subs;
    auto &interpOffs = offsets->interpreter_state.subs;
    auto head = runtimeOffs.interpreters_head.value(proc.io, pyRuntimeAddr);

    while (head.remote) {
        std::cerr << "found interpreter " << head << "\n";
        interps.push_back(head);
        head = interpOffs.next.value(proc.io, head);
    }
    return interps;
}

std::vector<Remote<PyThreadState *>>
Target::threads(Remote<PyInterpreterState *> interp) {
    std::vector<Remote<PyThreadState *>> threads;
    auto &interpOffs = offsets->interpreter_state.subs;
    auto &threadOffs = offsets->thread_state.subs;
    auto head = interpOffs.threads_head.value(proc.io, interp);
    while (head.remote) {
        std::cerr << "found thread " << head << "\n";
        threads.push_back(head);
        head = threadOffs.next.value(proc.io, head);
    }
    return threads;
}


Target::~Target() = default;

}
