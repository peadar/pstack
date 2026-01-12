#include "libpstack/pyrdb.h"
#include <map>
#include <charconv>
#include <fstream>
#include <string_view>

namespace pstack::Py {

// Minimal header from _PyRuntime to find the version, and verify the magic cookie.
struct Header {
    std::array<char, 8> cookie;
    static constexpr std::string_view expectedCookie { "xdebugpy" };
    uint64_t version;
    auto operator <=> (const Header &rhs) const = default;
};

struct PyTypes {
    std::map<Remote<PyTypeObject *>, std::string> names;
    Target &target;
    PyType<PyLongObject> pyLong_Type;
    PyType<PyLongObject> pyBool_Type;
    PyType<PyUnicodeObject> pyUnicode_Type;
    PyType<PyCodeObject> pyCode_Type;
    PyType<PyNoneType> pyNone_Type;
    PyType<PyTupleObject> pyTuple_Type;
    PyType<PyListObject> pyList_Type;
    PyType<PyBytesObject> pyBytes_Type;
    Remote<PyTypeObject *> lookupTypeSymbol(const char *name);
    PyTypes(Target &target_)
     : target(target_)
     , pyLong_Type{lookupTypeSymbol("PyLong_Type")}
     , pyBool_Type{lookupTypeSymbol("PyBool_Type")}
     , pyUnicode_Type{lookupTypeSymbol("PyUnicode_Type")}
     , pyCode_Type{lookupTypeSymbol("PyCode_Type")}
     , pyNone_Type{lookupTypeSymbol("_PyNone_Type")}
     , pyTuple_Type{lookupTypeSymbol("PyTuple_Type")}
     , pyList_Type{lookupTypeSymbol("PyList_Type")}
     , pyBytes_Type{lookupTypeSymbol("PyBytes_Type")}
    {
    }
};

Remote<PyTypeObject *>
PyTypes::lookupTypeSymbol(const char *name) {
    auto value = reinterpret_cast<PyTypeObject *>(target.proc.resolveSymbol(name, false));
    if (value == nullptr) {
        std::cerr << "no type for " << name << "\n";
    }
    Remote<PyTypeObject *> remote {value};
    names[remote] = name;
    return remote;
}

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
#define OFF(type, k) Off<type> k{this, #k}

struct RuntimeStateOffsets : OffsetContainer {
    template<typename Field> using Off = Offset<_PyRuntimeState, Field>;
    OFF(PyThreadState *, finalizing);
    OFF(PyInterpreterState *, interpreters_head);
};

struct PyObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyObject, Field>;
    OFF(PyTypeObject *, ob_type);
};

struct InterpreterStateOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyInterpreterState, Field>;
    OFF(int64_t, id);
    OFF(PyInterpreterState*, next);
    OFF(PyThreadState*, threads_head);
    OFF(PyThreadState*, threads_main);
    OFF(_gc_runtime_state, gc);
    OFF(PyObject *, imports_modules);
    OFF(PyObject *, sysdict);
    OFF(PyObject *, builtins);
    OFF(_gil_runtime_state *, ceval_gil);
    OFF(_gil_runtime_state, gil_runtime_state);
    OFF(int, gil_runtime_state_locked);
    OFF(void *, gil_runtime_state_enabled); // XXX? zero.
    OFF(PyThreadState *, gil_runtime_state_holder);
    OFF(uint64_t, code_object_generation);
    OFF(uint64_t, tlbc_generation);
};

struct PyTypeObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyTypeObject, Field>;
    OFF(char *, tp_name);
    OFF(void *, tp_repr);
    OFF(PyObject *, tp_flags);
};

struct ThreadStateOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyThreadState, Field>;
    OFF(PyThreadState *, prev);
    OFF(PyThreadState *, next);
    OFF(PyInterpreterState *, interp);
    OFF(_PyInterpreterFrame *, current_frame);
    OFF(unsigned long, thread_id);
    OFF(unsigned long, native_thread_id);
    OFF(_PyStackChunk *, datastack_chunk);
    OFF(unsigned int, status);
};

struct InterpreterFrameOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<_PyInterpreterFrame, Field>;
    OFF(_PyInterpreterFrame *, previous);
    OFF(PyObject *, executable);
    OFF(char *, instr_ptr); // actually, _Py_CODEUNIT *, but line tables etc treat offsets as character pointers.
    OFF(_PyStackRef, localsplus);
    OFF(char, owner);
    OFF(_PyStackRef *, stackpointer);
    OFF(void *, tlbc_index); // XXX?
};

struct CodeObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyCodeObject, Field>;
    OFF(PyObject *, filename);
    OFF(PyUnicodeObject *, name);
    OFF(PyObject *, qualname);
    OFF(PyBytesObject *, linetable);
    OFF(int, firstlineno);
    OFF(int, argcount);
    OFF(PyTupleObject *, localsplusnames);
    OFF(PyObject *, localspluskinds);
    OFF(char, co_code_adaptive);
    OFF(void, co_tlbc); // XXX?
};

struct PyBytesObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyBytesObject, Field>;
    OFF(ssize_t, ob_size);
    OFF(unsigned char, ob_sval);
};

struct PyASCIIState {
    unsigned int interned : 2;
    unsigned int kind : 3;
    unsigned int compact : 1;
    unsigned int ascii : 1;
    unsigned int statically_allocated : 1;
};

struct UnicodeObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyUnicodeObject, Field>;
    OFF(ssize_t, asciiobject_size);
    OFF(PyASCIIState, state);
    OFF(ssize_t, length);
};

struct PyTupleObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyTupleObject, Field>;
    OFF(PyObject *, ob_item);
    OFF(ssize_t, ob_size);
};

struct PyLongObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyLongObject, Field>;
    OFF(uintptr_t, lv_tag);
    OFF(unsigned int, ob_digit);
};

struct PyListObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyListObject, Field>;
    OFF(ssize_t, ob_size);
    OFF(PyObject **, ob_item);
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
    PyTupleObjectOffsets tuple_object;
    PyTypeObjectOffsets type_object;
    PyLongObjectOffsets long_object;
    PyListObjectOffsets list_object;
    PyBytesObjectOffsets bytes_object;
    RootOffsets(uint64_t version, Reader::csptr io, uintptr_t object);
    ~RootOffsets();
};

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
        else if (field == "bytes_object")
            bytes_object.parse(is, io, object);
        else if (field == "tuple_object")
            tuple_object.parse(is, io, object);
        else if (field == "type_object")
            type_object.parse(is, io, object);
        else if (field == "long_object")
            long_object.parse(is, io, object);
        else if (field == "list_object")
            list_object.parse(is, io, object);
        else
            skip<unsigned>(is);
    });
}

RootOffsets::~RootOffsets() = default;

void
Target::dump(std::ostream &os, const Remote<char *> &charptr) const {
    os << '"' << proc.io->readString(reinterpret_cast<Elf::Addr>(charptr.remote)) << '"';
}

void
Target::dump(std::ostream &os, const Remote<PyTupleObject *> &charptr) const {
    auto count = fetch(offsets->tuple_object.ob_size(charptr));
    auto items = fetchArray(offsets->tuple_object.ob_item(charptr), count);
    os << "( ";
    const char *sep = "";
    for (auto &item : items) {
        os << sep << str(item);
        sep = ", ";
    }
    os << " )";
}

void
Target::dump(std::ostream &os, const Remote<PyListObject *> &listobj) const {
    auto count = fetch(offsets->list_object.ob_size(listobj));
    auto items = fetch(offsets->list_object.ob_item(listobj));
    auto itemsVec = fetchArray(items, count);
    os << "[ ";
    const char *sep = "";
    for (auto &item : itemsVec) {
        os << sep << str(item);
        sep = ", ";
    }
    os << " ]";
}



void
Target::dump(std::ostream &os, const Remote<PyObject *> &remote) const {
    if (!remote)
        os << "(null)";
    else if (auto str = cast(types->pyUnicode_Type, remote); str)
        dump(os, str);
    else if (auto l = cast(types->pyLong_Type, remote); l)
        dump(os, l);
    else if (auto t = cast(types->pyTuple_Type, remote); t)
        dump(os, t);
    else if (auto l = cast(types->pyList_Type, remote); l)
        dump(os, l);
    else if (auto l = cast(types->pyBool_Type, remote); l)
        dump(os, l);
    else if (auto l = cast(types->pyBytes_Type, remote); l)
        dump(os, l);
    else if (auto l = cast(types->pyNone_Type, remote); l)
        os << "None";
    else {
        auto type = pyType(remote);
        os << remote << " - opaque type " ;
        try {
            dump(os, fetch(offsets->type_object.tp_name(type)));
        }
        catch (...) {
            os << "(unknown)";
        }
    }
}

void
Target::dump(std::ostream &os, const Remote<PyLongObject *> &remote) const {
    auto type = pyType(Remote<PyObject *>(reinterpret_cast<PyObject *>(remote.remote)));
    if (type == types->pyBool_Type.typeObject) {
        os << (fetch(offsets->long_object.ob_digit(remote)) ? "True" : "False");
    } else {
        os << fetch(offsets->long_object.ob_digit(remote));
    }
}

struct Escape { unsigned char c; };
std::ostream &
operator << (std::ostream &os, const Escape &e) {
    if (e.c < 128 && e.c >= 32) {
        return os << char(e.c);
    }
    return os << "\\x" << std::setw(2) << std::setfill('0') << std::hex << int(e.c) << std::dec;
}


void
Target::dump(std::ostream &os, const Remote<PyBytesObject *> &remote) const {
    auto sz = fetch(offsets->bytes_object.ob_size(remote));
    auto vec = fetchArray(offsets->bytes_object.ob_sval(remote), sz);
    for (auto c : vec) {
        os << Escape{c};
    }

}


void
Target::dump(std::ostream &os, const Remote<PyUnicodeObject *> &remote) const {
    const auto &unicode = offsets->unicode_object;
    auto state = fetch(unicode.state(remote));
    auto objoff = uintptr_t(remote.remote);
    auto length = fetch(unicode.length(remote));

    uintptr_t dataAddr;
    if (state.compact) {
        // Compaact form. Data follows the object.
        dataAddr = objoff + (state.ascii ? unicode.asciiobject_size.off : unicode.size - sizeof (uintptr_t));

    } else {
        // non-compact form - data is pointed to by the pointer at the end of the PyUnicodeObject.
        Remote<uintptr_t *> dataAddrPtr;
        dataAddrPtr.remote = reinterpret_cast<uintptr_t *>(objoff + unicode.size - sizeof(uintptr_t));
        dataAddr = fetch(dataAddrPtr);
    }
    if (state.kind == 1) {
        Remote<char *> dataptr { reinterpret_cast<char *>(dataAddr) };
        std::vector<char> data;
        data = fetchArray(dataptr, length);
        os << std::string_view{data.data(), data.size()};
    } else if (state.kind == 2) {
        // data is 2-byte unicode. Convert to UTF-8
        Remote<uint16_t *> dataptr { reinterpret_cast<uint16_t *>(dataAddr) };
        std::vector<uint16_t> data;
        data = fetchArray(dataptr, length);
        for (auto c : data)
            os << UTF8(c);
    } else if (state.kind == 4) {
        // data is 4-byte unicode. Convert to UTF-8
        Remote<uint32_t *> dataptr { reinterpret_cast<uint32_t *>(dataAddr) };
        std::vector<uint32_t> data;
        data = fetchArray(dataptr, length);
        for (auto c : data)
            os << UTF8(c);
    } else {
        os << "<string of unsupported kind " << state.kind << ">";
    }
}

std::string_view
Target::typeName(Remote<PyTypeObject *> remote) const {
    auto it = types->names.find(remote);
    if (it != types->names.end())
        return it->second;
    return "(unknown)";
}

Remote<PyTypeObject *>
Target::pyType(Remote<PyObject *> remote) const {
    return fetch(offsets->pyobject.ob_type(remote));
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

        // The start of the section has three distinct interpretations:
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
        auto headerInProc = fetch(Remote<Header *>{reinterpret_cast<Header *>(secaddr)});

        auto cookieInProc = std::string_view(headerInProc.cookie.begin(), headerInProc.cookie.end());
        if (cookieInProc != Header::expectedCookie) {
            *proc.context.debug << "bad cookie in " << sec.io()->filename() << ", skipping\n";
            continue;
        }

        pyRuntime.remote = reinterpret_cast<_PyRuntimeState *>(secaddr);
        offsets = make_unique<RootOffsets>(headerInProc.version, proc.io, secaddr);
        dumpBacktrace(std::cout);
        return;
    }
    throw (Exception() << "no python interpreter found");
}

struct LineDelta {
    int line;
    unsigned code;
    bool noline;
};

auto checknext(auto &i, auto e) {
    if (i == e)
        throw (Exception() << "end of data reached while decoding varint");
    return *i++;
}

static inline int
read_varint(auto &i, auto e) {
    unsigned int read = checknext(i, e);
    unsigned int val = read & 63;
    unsigned int shift = 0;
    while (read & 64) {
        read = checknext(i, e);
        shift += 6;
        val |= (read & 63) << shift;
    }
    return val;
}

static int
read_signed_varint(auto &i, auto e) {
    unsigned int uval = read_varint(i, e);
    if (uval & 1)
        return -(int)(uval >> 1);
    return uval >> 1;
}

LineDelta read_deltas(auto &cur, auto end) {
    auto header = checknext(cur, end);
    auto insn = (header >> 3) & 0xf; // get bits 3-6.
    unsigned code_delta = ((header & 0x7) + 1) * sizeof(uint16_t);

    switch (insn) {
        case 0 ... 9: // PY_CODE_LOCATION_INFO_SHORT0...9. Only impact column.
            checknext(cur, end); // short column - byte value for column.
            return { 0, code_delta, false };

        case 10 ... 12: // PY_CODE_LOCATION_INFO_ONE_LINE0...2;
            checknext(cur, end); // column data - two bytes for start/end.
            checknext(cur, end);
            return { insn - 10, code_delta, false };

        case 13: // PY_CODE_LOCATION_INFO_NO_COLUMNS:
            return { read_signed_varint( cur, end ), code_delta, false };

        case 14: { // PY_CODE_LOCATION_INFO_LONG:
            auto line_delta = read_signed_varint( cur, end );
            // discard the "end" line data, and column data.
            read_signed_varint( cur, end );
            read_signed_varint( cur, end );
            read_signed_varint( cur, end );
            return { line_delta, code_delta, false };
        }

        case 15: // PY_CODE_LOCATION_INFO_NONE:
            return { 0, code_delta, true };

        default:
            throw Exception() << "unexpected instruction in line table: " << int(header) << "\n";
    }
}

void Target::dumpBacktrace(std::ostream &os) const {
    Procman::StopProcess here(&proc);
    auto &threadOffs = offsets->thread_state;
    auto &frameOffs = offsets->interpreter_frame;
    for (auto i : interpreters()) {
        os << "interpreter " << i << "\n";
        for (auto t : threads(i)) {
            auto id = fetch(threadOffs.thread_id(t));
            auto native_id = fetch(threadOffs.native_thread_id(t));
            os << "thread id: " << id << ", native id: " << native_id << "\n";
            auto frame = fetch(threadOffs.current_frame(t));
            while (frame) {
                auto executable = fetch(frameOffs.executable(frame));
                auto clear = (uintptr_t)executable.remote;
                clear &= -8LL;
                executable = { reinterpret_cast<PyObject *>(clear) };
                auto code = cast(types->pyCode_Type, executable);
                if (code) {
                    auto name = fetch(offsets->code_object.name(code));
                    auto file = fetch(offsets->code_object.filename(code));
                    auto instr_ptr = fetch(offsets->interpreter_frame.instr_ptr(frame));
                    auto instr_off = instr_ptr.remote - offsets->code_object.co_code_adaptive(code).remote;
                    auto firstline = fetch(offsets->code_object.firstlineno(code));
                    auto linetable = fetch(offsets->code_object.linetable(code));
                    // Read the entire line table into memory.
                    auto linetable_size = fetch(offsets->bytes_object.ob_size(linetable));
                    auto linetable_data = fetchArray(offsets->bytes_object.ob_sval(linetable), linetable_size);
                    int line = firstline;
                    auto i = linetable_data.begin();
                    auto e = linetable_data.end();
                    for (unsigned codeloc = 0; i != e; ) {
                        auto deltas = read_deltas(i, e);
                        line += deltas.line;
                        codeloc += deltas.code;
                        if (codeloc >= instr_off)
                            break;
                    }
                    os << str(name) << " in " << str(file) << ":" << line;
                    [[maybe_unused]] auto argCount = fetch(offsets->code_object.argcount(code));
                    auto lnames = fetch(offsets->code_object.localsplusnames(code));
                    auto localCount = fetch(offsets->tuple_object.ob_size(lnames));
                    auto nameVec = fetchArray(offsets->tuple_object.ob_item(lnames), localCount);
                    auto valueVec = fetchArray(offsets->interpreter_frame.localsplus(frame), localCount);
                    os << "\n";
                    for (ssize_t i = 0; i < localCount; ++i) {
                        auto name = nameVec[i];
                        auto value = valueVec[i];
                        os << "\t\t" << str(name) << ": ";
                        if ((value & 3) == 3) {
                            os << (value >> 2);
                        } else {
                            auto tval = Remote{reinterpret_cast<PyObject *>(value & ~3)};
                            os << str(tval);
                        }
                        os << "\n";
                    }
                } else {
                    os << "(unknown frame type " << typeName(pyType(executable)) << ")";
                }
                os << "\n";
                frame = fetch(frameOffs.previous(frame));
            }
        }
        os << "\n";
    }
}

std::vector<Remote<PyInterpreterState *>>
Target::interpreters() const {
    return followList(pyRuntime, offsets->runtime_state.interpreters_head, offsets->interpreter_state.next);
}

std::vector<Remote<PyThreadState *>>
Target::threads(Remote<PyInterpreterState *> interp) const {
    return followList(interp, offsets->interpreter_state.threads_head, offsets->thread_state.next);
}

Target::~Target() = default;

}
