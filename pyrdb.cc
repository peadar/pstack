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
    PyType<PyDictObject> pyDict_Type;
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
     , pyDict_Type{lookupTypeSymbol("PyDict_Type")}
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

RawOffset::RawOffset(OffsetContainer *container_, std::string_view name_, uint64_t default_off) : off(default_off) {
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
        // Only warn if the field doesn't have a hardcoded default
        if (value->off == 0xbaadf00d) {
            std::cerr << "field " << name << " not found\n";
        }
    }
}

// Containers for offsets, as found in substructures of PyDebugOffsets
// For each, we create an Offset object with appropriate container and field
// types for each offset. As we parse the JSON, we will populate the offsets as
// we find them in the process.
#define OFF(type, k) Off<type> k{this, #k}
#define OFF_DEFAULT(type, k, def) Off<type> k{this, #k, def}

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
    OFF(unsigned long, tp_flags);
    // tp_dictoffset not in debug offsets, hardcode for Python 3.14 64-bit (0x120)
    OFF_DEFAULT(ssize_t, tp_dictoffset, 288);
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

// Forward declaration
struct PyDictValues;

struct PyDictObjectOffsets : OffsetContainer {
    template <typename Field> using Off = Offset<PyDictObject, Field>;
    OFF(PyDictKeysObject *, ma_keys);
    OFF(PyDictValues *, ma_values);  // Changed to PyDictValues* in Python 3.11+
};

// We parse this out of the JSON file representing the _PyDebugOffsets type.
struct RootOffsets {
    uint64_t free_threaded = 0;  // Read from JSON: 1 for free-threaded build, 0 otherwise
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
    PyDictObjectOffsets dict_object;
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
        if (field == "free_threaded") {
            auto offset = parseInt<uint64_t>(is);
            io->readObj(object + offset, &free_threaded);
        }
        else if (field == "interpreter_state")
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
        else if (field == "dict_object")
            dict_object.parse(is, io, object);
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

// these are correct for python 3.14
struct PyDictKeysObject {
    ssize_t dk_refcnt;
    uint8_t dk_log2_size;
    uint8_t dk_log2_index_bytes;
    uint8_t dk_kind;
    uint32_t dk_version;
    ssize_t dk_usable;
    ssize_t dk_nentries;
    char dk_indices[0];
};

struct PyDictKeyEntry {
    long me_hash;
    PyObject *me_key;
    PyObject *me_value;
};

struct PyDictUnicodeEntry {
    PyObject *me_key;
    PyObject *me_value;
};

enum DictKeysKind {
    DICT_KEYS_GENERAL = 0,
    DICT_KEYS_UNICODE = 1,
    DICT_KEYS_SPLIT = 2
};

struct PyDictValues {
    uint8_t capacity;
    uint8_t size;
    uint8_t embedded;
    uint8_t valid;
    PyObject *values[1];
};

// Local structure definitions to calculate offsets with offsetof()
// These mirror the real Python structures but only include fields we need

struct LocalPyObject {
    ssize_t ob_refcnt;
    PyTypeObject *ob_type;
};

struct LocalPyVarObject {
    LocalPyObject ob_base;
    ssize_t ob_size;
};

// PyTypeObject - only fields up to tp_basicsize which we need
struct LocalPyTypeObject {
    LocalPyVarObject ob_base;
    const char *tp_name;
    ssize_t tp_basicsize;
    // ... rest not needed for offset calculation
};

// Slot structures - we just need their sizes for offset calculation
struct LocalPyAsyncMethods {
    void *am_await;
    void *am_aiter;
    void *am_anext;
    void *am_send;
};

struct LocalPyNumberMethods {
    void *slots[36];  // 36 function pointers in Python 3.14
};

struct LocalPyMappingMethods {
    void *mp_length;
    void *mp_subscript;
    void *mp_ass_subscript;
};

struct LocalPySequenceMethods {
    void *slots[10];  // 10 function pointers
};

struct LocalPyBufferProcs {
    void *bf_getbuffer;
    void *bf_releasebuffer;
};

// Fields that come after PyTypeObject in PyHeapTypeObject
struct PyHeapTypeFields {
    LocalPyAsyncMethods as_async;
    LocalPyNumberMethods as_number;
    LocalPyMappingMethods as_mapping;
    LocalPySequenceMethods as_sequence;
    LocalPyBufferProcs as_buffer;
    PyObject *ht_name;
    PyObject *ht_slots;
    PyObject *ht_qualname;
    PyDictKeysObject *ht_cached_keys;
};

// Template function to scan and dump dict entries
// Works with both PyDictUnicodeEntry and PyDictKeyEntry
// values_array is used for split dicts (ma_values) and inline values
template<typename EntryType>
void
Target::scanDictEntries(std::ostream &os, const PyDictKeysObject &keys,
                        const Remote<EntryType *> &entries,
                        Remote<PyObject **> values_array) const {
    const char *sep = "";
    for (ssize_t i = 0; i < keys.dk_nentries; ++i) {
        auto entry = fetch(Remote{ entries.remote + i });
        intptr_t entryInt = reinterpret_cast<intptr_t>(entry.me_key);
        // Skip DKIX_{EMPTY,DUMMY,ERROR,KEY_CHANGED,....}
        if (entryInt < 0 && entryInt > -16)
            continue;
        os << sep;
        dump(os, Remote{entry.me_key});
        os << ": ";
        if (values_array) {
            // Split dict or inline values: values are in separate array
            auto value = fetch(Remote<PyObject **>{values_array.remote + i});
            dump(os, Remote<PyObject *>{value});
        } else {
            // Combined dict: value is in the entry
            dump(os, Remote<PyObject *>{entry.me_value});
        }
        sep = ", ";
    }
}

void
Target::dump(std::ostream &os, const Remote<PyDictObject *> &dictobj) const {

    auto ma_keys = fetch(offsets->dict_object.ma_keys(dictobj));
    auto ma_values = fetch(offsets->dict_object.ma_values(dictobj));

    if (!ma_keys) {
        os << "{}";
        return;
    }

    auto keys = fetch(ma_keys);

    // Sanity check values
    if (keys.dk_log2_size > 30 || keys.dk_nentries < 0 || keys.dk_nentries > 8000000) {
        os << "{<invalid dict structure: log2_size=" << int(keys.dk_log2_size)
           << ", nentries=" << keys.dk_nentries << ">}";
        return;
    }

    size_t dict_size = size_t(1) << keys.dk_log2_size;

    // Size of indices array depends on dict_size
    size_t index_size =
        dict_size <= 0xff ? 1 :
        dict_size <= 0xffff ? 2 :
        dict_size <= 0xffffffff ? 4 :
        8;

    // dk_entries starts after dk_indices
    uintptr_t keys_addr = reinterpret_cast<uintptr_t>(ma_keys.remote);
    uintptr_t entries_addr = keys_addr + sizeof(PyDictKeysObject) + dict_size * index_size;

    os << "{ ";

    // In Python 3.11+, ma_values is a PyDictValues*, so we need to skip past the metadata
    Remote<PyObject **> values_array{};
    if (ma_values) {
        values_array = Remote<PyObject **>{reinterpret_cast<PyObject **>(
            reinterpret_cast<uintptr_t>(ma_values.remote) + offsetof(PyDictValues, values))};
    }

    if (keys.dk_kind == DICT_KEYS_UNICODE) {
        auto entries_ptr = Remote<PyDictUnicodeEntry *>{reinterpret_cast<PyDictUnicodeEntry *>(entries_addr)};
        scanDictEntries(os, keys, entries_ptr, values_array);
    } else {
        auto entries_ptr = Remote<PyDictKeyEntry *>{reinterpret_cast<PyDictKeyEntry *>(entries_addr)};
        scanDictEntries(os, keys, entries_ptr, values_array);
    }

    os << " }";
}

void
Target::dumpUserDefined(std::ostream &os, const Remote<PyObject *> &remote) const {
    // User-defined type or other type
    auto type = pyType(remote);
    os << "<";
    dump(os, fetch(offsets->type_object.tp_name(type)));
    os << " object";

    // For user-defined types, try to get the instance dictionary
    auto tp_flags = fetch(offsets->type_object.tp_flags(type));
    auto dictoffset = fetch(offsets->type_object.tp_dictoffset(type));

    constexpr uintptr_t Py_TPFLAGS_MANAGED_DICT = 0x10;  // 1 << 4
    constexpr uintptr_t Py_TPFLAGS_INLINE_VALUES = 0x4;   // 1 << 2

    // MANAGED_DICT_OFFSET depends on whether this is a free-threaded build
    // Free-threaded: -1 * sizeof(PyObject*) = -8 bytes
    // Standard: -3 * sizeof(PyObject*) = -24 bytes
    ssize_t MANAGED_DICT_OFFSET = offsets->free_threaded
        ? -1 * sizeof(PyObject*)
        : -3 * sizeof(PyObject*);

    if (tp_flags & Py_TPFLAGS_MANAGED_DICT) {
        uintptr_t instance_addr = reinterpret_cast<uintptr_t>(remote.remote);

        // Check if we have inline values (Python 3.13+)
        if (tp_flags & Py_TPFLAGS_INLINE_VALUES) {
            // Inline values: try materialized dict first
            auto dict_ptr = fetch(Remote<PyObject **>{reinterpret_cast<PyObject **>(instance_addr + MANAGED_DICT_OFFSET)});

            if (dict_ptr) {
                auto dict_remote = Remote<PyObject *>{dict_ptr};
                if (auto d = cast(types->pyDict_Type, dict_remote); d) {
                    os << " ";
                    dump(os, d);
                }
            } else {
                // Dict not materialized - read inline values
                // Get ht_cached_keys from PyHeapTypeObject
                // Offset = sizeof(PyTypeObject) + offset within PyHeapTypeFields
                size_t ht_cached_keys_offset = offsets->type_object.size + offsetof(PyHeapTypeFields, ht_cached_keys);

                // Read tp_basicsize and ht_cached_keys using Remote<>
                auto local_type = Remote<LocalPyTypeObject *>{reinterpret_cast<LocalPyTypeObject *>(type.remote)};
                auto tp_basicsize = fetch(local_type).tp_basicsize;

                uintptr_t type_addr = reinterpret_cast<uintptr_t>(type.remote);
                auto cached_keys_remote = fetch(Remote<PyDictKeysObject **>{reinterpret_cast<PyDictKeysObject **>(type_addr + ht_cached_keys_offset)});

                if (cached_keys_remote) {
                    // Read the shared keys object
                    auto keys = fetch(cached_keys_remote);

                    // Now read the inline values array
                    uintptr_t inline_values_addr = instance_addr + tp_basicsize;

                    // Calculate where entries are in the keys object
                    size_t dict_size = size_t(1) << keys.dk_log2_size;
                    size_t index_size =
                        dict_size <= 0xff ? 1 :
                        dict_size <= 0xffff ? 2 :
                        dict_size <= 0xffffffff ? 4 : 8;

                    uintptr_t keys_addr = reinterpret_cast<uintptr_t>(cached_keys_remote.remote);
                    uintptr_t entries_addr = keys_addr + sizeof(PyDictKeysObject) + dict_size * index_size;

                    os << " { ";

                    // Dump key-value pairs using shared scanDictEntries function
                    auto inline_values = Remote<PyObject **>{reinterpret_cast<PyObject **>(inline_values_addr + offsetof(PyDictValues, values))};

                    if (keys.dk_kind == DICT_KEYS_UNICODE || keys.dk_kind == DICT_KEYS_SPLIT) {
                        auto entries_ptr = Remote<PyDictUnicodeEntry *>{reinterpret_cast<PyDictUnicodeEntry *>(entries_addr)};
                        scanDictEntries(os, keys, entries_ptr, inline_values);
                    } else {
                        auto entries_ptr = Remote<PyDictKeyEntry *>{reinterpret_cast<PyDictKeyEntry *>(entries_addr)};
                        scanDictEntries(os, keys, entries_ptr, inline_values);
                    }

                    os << " }";
                } else {
                    os << " {<no cached keys>}";
                }
            }
        } else {
            // Managed dict without inline values
            auto dict_ptr = fetch(Remote<PyObject **>{reinterpret_cast<PyObject **>(instance_addr + MANAGED_DICT_OFFSET)});

            if (dict_ptr) {
                auto dict_remote = Remote<PyObject *>{dict_ptr};
                if (auto d = cast(types->pyDict_Type, dict_remote); d) {
                    os << " ";
                    dump(os, d);
                }
            }
        }
    } else  if (dictoffset >= 0) {
        uintptr_t instance_addr = reinterpret_cast<uintptr_t>(remote.remote);
        auto dict_ptr = fetch(Remote<PyObject **>{reinterpret_cast<PyObject **>(instance_addr + dictoffset)});

        if (dict_ptr) {
            auto dict_remote = Remote<PyObject *>{dict_ptr};
            if (auto d = cast(types->pyDict_Type, dict_remote); d) {
                os << " ";
                dump(os, d);
            }
        }
    }
    os << ">";
}

void
Target::dump(std::ostream &os, const Remote<PyObject *> &remote) const {
    if (!remote) {
        os << "(null)";
        return;
    }
    if (auto v = cast(types->pyUnicode_Type, remote); v)
        dump(os, v);
    else if (auto v = cast(types->pyLong_Type, remote); v)
        dump(os, v);
    else if (auto v = cast(types->pyTuple_Type, remote); v)
        dump(os, v);
    else if (auto v = cast(types->pyList_Type, remote); v)
        dump(os, v);
    else if (auto v = cast(types->pyBool_Type, remote); v)
        dump(os, v);
    else if (auto v = cast(types->pyBytes_Type, remote); v)
        dump(os, v);
    else if (auto v = cast(types->pyDict_Type, remote); v)
        dump(os, v);
    else if (auto v = cast(types->pyNone_Type, remote); v)
        os << "None";
    else
        dumpUserDefined(os, remote);
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

std::string
Target::typeName(Remote<PyTypeObject *> remote) const {
    #if 0
    auto it = types->names.find(remote);
    if (it != types->names.end())
        return it->second;
    #endif
    std::ostringstream os;
    os << proc.io->readString((uintptr_t)fetch(offsets->type_object.tp_name(remote)).remote);
    return os.str();
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
