#include "libpstack/pyrdb.h"
#include <map>
#include <charconv>
#include <fstream>
#include <string_view>

namespace pstack::Py {

struct PyASCIIState {
    unsigned int interned : 2;
    unsigned int kind : 3;
    unsigned int compact : 1;
    unsigned int ascii : 1;
    unsigned int statically_allocated : 1;
};

struct PyTypes {
    std::map<Remote<PyTypeObject *>, std::string> names;
    Target &target;
    PyType<PyUnicodeObject> pyUnicode_Type;
    PyType<PyCodeObject> pyCode_Type;
    PyType<PyObject> pyNone_Type;
    Remote<PyTypeObject *> lookupTypeSymbol(const char *name);
    PyTypes(Target &target_)
     : target(target_)
     , pyUnicode_Type{lookupTypeSymbol("PyUnicode_Type")}
     , pyCode_Type{lookupTypeSymbol("PyCode_Type")}
     , pyNone_Type{lookupTypeSymbol("_PyNone_Type")}
    {
    }
};

Remote<PyTypeObject *>
PyTypes::lookupTypeSymbol(const char *name) {
    auto value = reinterpret_cast<PyTypeObject *>(target.proc.resolveSymbol(name, false));
    Remote<PyTypeObject *> remote {value};
    names[remote] = name;
    return remote;
}

// Minimal header from _PyRuntime to find the version, and verify the magic cookie.
struct Header {
    std::array<char, 8> cookie;
    static constexpr std::string_view expectedCookie { "xdebugpy" };
    uint64_t version;
    auto operator <=> (const Header &rhs) const = default;
};

RawOffset::RawOffset(OffsetContainer *container_, std::string_view name_) {
    container_->fields[name_] = this;
}

void
OffsetContainer::parse(std::istream &is, const Reader::csptr &reader, uintptr_t object) {
    parseObject(is, [&](std::istream &is, std::string_view fieldName) {
        if (fieldName == "size") {
            auto sizeoff = parseInt<size_t>(is);
            reader->readObj(object + sizeoff, &size);
        } else {
            auto fieldi = fields.find(fieldName);
            if (fieldi != fields.end()) {
                fieldi->second->parse(is, reader, object);
                fields.erase(fieldi);
            } else {
                std::cerr << "unsupported/duplicate field " << fieldName << "\n";
                skip<uintptr_t>(is);
            }
        }
    });
    for (auto &[name, value] : fields) {
        std::cerr << "field " << name << " not found\n";
    }
}

// Containers for offsets, as found in substructures of PyDebugOffsets
// For each, we create an Offset object with appropriate container and field
// types for each offset. As we parse the JSON, we will populate the offsets as
// we find them in the process.

struct RuntimeStateOffsets : OffsetContainer {
    template<typename Field> using Off = Offset<_PyRuntimeState, Field>;
    Off<PyThreadState *> finalizing;
    Off<PyInterpreterState *> interpreters_head;
    RuntimeStateOffsets() 
        : finalizing(this, "finalizing")
        , interpreters_head(this, "interpreters_head")
    {}
};

struct PyObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyObject, Field>;
    Off<PyTypeObject *> ob_type;
    PyObjectOffsets() : ob_type(this, "ob_type") {}
};

struct InterpreterStateOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyInterpreterState, Field>;
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
        : id(this, "id")
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

struct ThreadStateOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyThreadState, Field>;
    Off<PyThreadState *> prev;
    Off<PyThreadState *> next;
    Off<PyInterpreterState *> interp;
    Off<_PyInterpreterFrame *> current_frame;
    Off<unsigned long> thread_id;
    Off<unsigned long> native_thread_id;
    Off<_PyStackChunk *> datastack_chunk;
    Off<unsigned int> status;
    ThreadStateOffsets()
        : prev(this, "prev")
        , next(this, "next")
        , interp(this, "interp")
        , current_frame(this, "current_frame")
        , thread_id(this, "thread_id")
        , native_thread_id(this, "native_thread_id")
        , datastack_chunk(this, "datastack_chunk")
        , status(this, "status")
    {}
};

struct InterpreterFrameOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<_PyInterpreterFrame, Field>;
    Off<_PyInterpreterFrame *> previous;
    Off<PyObject *> executable;
    Off<_Py_CODEUNIT> instr_ptr;
    Off<_PyStackRef> localsplus;
    Off<char> owner;
    Off<_PyStackRef *> stackpointer;
    Off<void *> tlbc_index; // XXX?
    InterpreterFrameOffsets()
        : previous(this, "previous")
        , executable(this, "executable")
        , instr_ptr(this, "instr_ptr")
        , localsplus(this, "localsplus")
        , owner(this, "owner")
        , stackpointer(this, "stackpointer")
        , tlbc_index(this, "tlbc_index")
    {}
};

struct CodeObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyCodeObject, Field>;
    Off<PyObject *> filename;
    Off<PyUnicodeObject *> name;
    Off<PyObject *> qualname;
    Off<PyObject *> linetable;
    Off<int> firstlineno;
    Off<int> argcount;
    Off<PyObject *> localsplusnames;
    Off<PyObject *> localspluskinds;
    Off<char> co_code_adaptive;
    Off<void> co_tlbc; // XXX?
    CodeObjectOffsets() 
        : filename(this, "filename")
        , name(this, "name")
        , qualname(this, "qualname")
        , linetable(this, "linetable")
        , firstlineno(this, "firstlineno")
        , argcount(this, "argcount")
        , localsplusnames(this, "localsplusnames")
        , localspluskinds(this, "localspluskinds")
        , co_code_adaptive(this, "co_code_adaptive")
        , co_tlbc(this, "co_tlbc")
    {}
};

struct UnicodeObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyUnicodeObject, Field>;
    Off<ssize_t> asciiobject_size;
    Off<PyASCIIState> state;
    Off<ssize_t> length;
    UnicodeObjectOffsets()
    : asciiobject_size(this, "asciiobject_size")
        , state(this, "state")
        , length(this, "length")
    {}
};

// We parse this out of the JSON file representing the _PyDebugOffsets type.
struct RootOffsets {
    RuntimeStateOffsets runtime_state;
    InterpreterStateOffsets interpreter_state;
    ThreadStateOffsets thread_state;
    InterpreterFrameOffsets interpreter_frame;
    CodeObjectOffsets code_object;
    UnicodeObjectOffsets unicode_object;
    PyObjectOffsets pyobject;
    RootOffsets(uint64_t version, Reader::csptr io, uintptr_t object);
    ~RootOffsets();
};

void
Target::dump(std::ostream &os, const Remote<PyObject *> &remote) const {
    if (remote.remote == 0) {
        os << "<null>";
        return;
    }
    if (auto str = cast(types->pyUnicode_Type, remote); str) {
        dump(os, str);
    }
}

void
Target::dump(std::ostream &os, const Remote<PyUnicodeObject *> &remote) const {
    auto state = offsets->unicode_object.state.value(proc.io, remote);

    Remote<char *> dataptr;
    auto rawptr = uintptr_t(remote.remote);
    auto length = offsets->unicode_object.length.value(proc.io, remote);
    if (state.compact) {
        // Compaact form. Data follows the object.
        size_t dataoff = state.ascii ?
            offsets->unicode_object.asciiobject_size.off :
            offsets->unicode_object.size - sizeof (uintptr_t);
        dataptr.remote = reinterpret_cast<char *>(rawptr + dataoff);

    } else {
        // non-compact form - data is pointed to by the pointer at the end of the PyUnicodeObject.
        Remote<char **> dataptrptr;
        dataptrptr.remote = reinterpret_cast<char **>(rawptr + offsets->unicode_object.size - sizeof(uintptr_t));
        dataptr = dataptrptr.fetch(proc.io);
    }
    std::vector<char> data;
    if (state.kind == 1) {
        data = dataptr.fetchArray(proc.io, length);
    }
    os << std::string_view{data.data(), data.size()};

    #if 0
    os
        << remote << "{ state: { "
            << "{ kind: " << state.kind
            << ", interned: " << state.interned
            << ", compact: " << state.compact
            << ", ascii: " << state.ascii
            << ", statically_allocated: " << state.statically_allocated
            << " }"
        << ", length: " << length
        << ", asciiobject_size: " << asciiobject_size
        << " }";
    #endif
}

RootOffsets::RootOffsets(uint64_t versionExpected, Reader::csptr io, uintptr_t object)
{
    std::array<char, 16> chars;
    auto [ end, ec ] = std::to_chars(chars.begin(), chars.end(), versionExpected, 16);
    std::string name = std::string(chars.begin(), end) + ".json";
    std::ifstream in(name);
    parseObject(in, [&](std::istream &is, std::string_view field) {
        if (field == "interpreter_state")
            interpreter_state.parse(is, io, object);
        else if (field == "thread_state")
            thread_state.parse(is, io, object);
        else if (field == "runtime_state")
            runtime_state.parse(is, io, object);
        else if (field == "interpreter_frame")
            interpreter_frame.parse(is, io, object);
        else if (field == "code_object")
            code_object.parse(is, io, object);
        else if (field == "unicode_object")
            unicode_object.parse(is, io, object);
        else if (field == "pyobject")
            pyobject.parse(is, io, object);
        else {
            skip<unsigned>(is);
        }
    });
}

RootOffsets::~RootOffsets() {}

std::string_view
Target::typeName(Remote<PyTypeObject *> remote) const {
    auto it = types->names.find(remote);
    if (it != types->names.end()) {
        return it->second;
    }
    return "(unknown)";
}

Remote<PyTypeObject *>
Target::pyType(Remote<PyObject *> remote) const {
    return offsets->pyobject.ob_type.value(proc.io, remote);
}

Target::Target(Procman::Process &proc_)
    : proc{proc_}
    , types{std::make_unique<PyTypes>(*this)}
{
    // find a python interpreter. The first thing with the right section with the right contents will do.
    for (auto &[addr, mapped] : proc.objects) {
        auto &sec = mapped.object(proc.context)->getSection(".PyRuntime", SHT_PROGBITS);
        if (!sec)
            continue;

        // The start of the section has three distinct uses:
        // 1: the "header", which is the magic number and version. That
        // structure is hard-coded here
        //
        // 2: the _Py_DebugOffsets, which must
        // start with the header, but the rest of the content is defined by
        // offsets in the JSON file
        //
        // 3: The _PyRuntime - which must start with _PyDebugOffsets. We know
        // this has certain fields, and the JSON file says where they are, along
        // with locating fields in other types we may have to walk
        //
        auto secaddr = addr + sec.shdr.sh_addr;
        auto headerInProc = Remote<Header *>{reinterpret_cast<Header *>(secaddr)}.fetch(proc.io);

        auto cookieInProc = std::string_view(headerInProc.cookie.begin(), headerInProc.cookie.end());
        if (cookieInProc != Header::expectedCookie) {
            *proc.context.debug << "bad cookie in " << sec.io()->filename() << ", skipping\n";
            getppid();
            continue;
        }

        pyRuntimeAddr.remote = reinterpret_cast<_PyRuntimeState *>(secaddr);
        offsets = make_unique<RootOffsets>(headerInProc.version, proc.io, secaddr);
        dumpBacktrace(std::cerr);
        return;
    }
    throw (Exception() << "no python interpreter found");
}

void Target::dumpBacktrace(std::ostream &os) const {
    auto &threadOffs = offsets->thread_state;
    auto &frameOffs = offsets->interpreter_frame;
    for (auto i : interpreters()) {
        os << "interp " << i << "\n";
        for (auto t : threads(i)) {
            auto id = threadOffs.thread_id.value(proc.io, t);
            auto native_id = threadOffs.native_thread_id.value(proc.io, t);
            os << "thread id: " << id << ", native id: " << native_id << "\n";
            auto frame = threadOffs.current_frame.value(proc.io, t);
            while (frame.remote) {
                auto executable = frameOffs.executable.value(proc.io, frame);
                auto clear = (uintptr_t)executable.remote;
                [[maybe_unused]] auto mode = clear & (8-1);
                clear &= -8LL;
                executable.remote = reinterpret_cast<PyObject *>(clear);
                auto code = cast(types->pyCode_Type, executable);
                os << "\t";
                if (code) {
                    auto name = offsets->code_object.name.value(proc.io, code);
                    dump(os, name);
                } else {
                    os << "(unknown frame type " << typeName(pyType(executable)) << ")";
                }
                os << "\n";
                frame = frameOffs.previous.value(proc.io, frame);
            }
        }
        os << "\n";
    }
}

std::vector<Remote<PyInterpreterState *>>
Target::interpreters() const {
    std::vector<Remote<PyInterpreterState *>> interps;
    auto &runtimeOffs = offsets->runtime_state;
    auto &interpOffs = offsets->interpreter_state;
    auto head = runtimeOffs.interpreters_head.value(proc.io, pyRuntimeAddr);
    while (head.remote) {
        interps.push_back(head);
        head = interpOffs.next.value(proc.io, head);
    }
    return interps;
}

std::vector<Remote<PyThreadState *>>
Target::threads(Remote<PyInterpreterState *> interp) const {
    std::vector<Remote<PyThreadState *>> threads;
    auto &interpOffs = offsets->interpreter_state;
    auto &threadOffs = offsets->thread_state;
    auto head = interpOffs.threads_head.value(proc.io, interp);
    while (head.remote) {
        threads.push_back(head);
        head = threadOffs.next.value(proc.io, head);
    }
    return threads;
}
Target::~Target() = default;

template<typename To> Remote<To *> Target::cast(const PyType<To> &to, Remote<PyObject *> from) const {
    if (pyType(from) == to.typeObject) {
        return { reinterpret_cast<To *>(from.remote) };
    }
    return {0};
}

}
