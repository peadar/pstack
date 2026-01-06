#include "libpstack/pyrdb.h"
#include <charconv>
#include <fstream>
#include <array>
#include <string_view>

namespace pstack::Py {

std::unique_ptr<Structure> parseContainer(std::istream &in) {
    auto container = std::make_unique<Structure>();
    parseObject(in, [&](std::istream &is, std::string_view fieldName) {
            auto &field = container->fields[std::string(fieldName)];
            switch (peekType(is)) {
            case Object:
                field = parseContainer(is);
                break;
            case Number:
                field = parseInt<int>(is);
                break;
            case ::pstack::Null:
                field = parseNull(is);
                break;
            default:
                throw (Exception{} << "unexpected JSON type");
            }
    });
    return container;
}

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

// Member descriptor structures (for __slots__)
struct PyMemberDef {
    const char *name;
    int type;
    ssize_t offset;
    int flags;
    const char *doc;
};


// Minimal header from _PyRuntime to find the version, and verify the magic cookie.
struct Header {
    std::array<char, 8> cookie;
    static constexpr std::string_view expectedCookie { "xdebugpy" };
    uint64_t version;
};

struct PyTypes {
    Remote<PyTypeObject *> lookupTypeSymbol(const char *name);
    Target &target;
    PyTypes(Target &target_) : target(target_) { }
    PyType<PyLongObject> pyLong_Type {lookupTypeSymbol("PyLong_Type")};
    PyType<PyLongObject> pyBool_Type {lookupTypeSymbol("PyBool_Type")};
    PyType<PyUnicodeObject> pyUnicode_Type {lookupTypeSymbol("PyUnicode_Type")};
    PyType<PyCodeObject> pyCode_Type {lookupTypeSymbol("PyCode_Type")};
    PyType<PyNoneType> pyNone_Type {lookupTypeSymbol("_PyNone_Type")};
    PyType<PyTupleObject> pyTuple_Type{lookupTypeSymbol("PyTuple_Type")};
    PyType<PyListObject> pyList_Type {lookupTypeSymbol("PyList_Type")};
    PyType<PyBytesObject> pyBytes_Type {lookupTypeSymbol("PyBytes_Type")};
    PyType<PyDictObject> pyDict_Type {lookupTypeSymbol("PyDict_Type")};
};

Remote<PyTypeObject *>
PyTypes::lookupTypeSymbol(const char *name) {
    auto value = reinterpret_cast<PyTypeObject *>(target.proc.resolveSymbol(name, false));
    if (value == nullptr) {
        std::cerr << "no type for " << name << "\n";
    }
    return {value};
}

RawOffset::RawOffset(OffsetContainer *container_, std::string_view name_, std::initializer_list<std::string_view> debugPath_, uint64_t default_off) : off(default_off) {
    container_->fields[name_] = this;
    debugPath = debugPath_;
    if (debugPath.empty()) {
        debugPath.push_back(name_);
    }
}

void
OffsetContainer::populate(const Structure *top, const Structure *topDebugOffsets, const Reader::csptr &reader, uintptr_t object) {

    const Structure *typeObject = top->substructure(typeName);
    auto debugOffsets = topDebugOffsets && debugOffsetsField ? topDebugOffsets->substructure( debugOffsetsField ) : nullptr;

    if (debugOffsets) {
        if ( auto sizei = debugOffsets->fields.find("size"); sizei != debugOffsets->fields.end())
            size = reader->readObj<size_t>(object + std::get<int>(sizei->second) );
    } else if (typeObject) {
        if ( auto sizei = typeObject->fields.find("<size>"); sizei != typeObject->fields.end())
            size = std::get<int>(sizei->second);
    }


    for (auto &[fieldName, fieldOffset] : fields) {
        bool done = false;
        if (debugOffsets) {
            auto offsetoffset = debugOffsets->fieldOffset(fieldName);
            if (offsetoffset) {
                fieldOffset->off = reader->readObj<size_t>(object + *offsetoffset);
                done = true;
            }
        }
        const Structure *obj = typeObject;
        if (!done && typeObject) {
            for (auto &ctr : fieldOffset->debugPath |
                    std::views::take(fieldOffset->debugPath.size() - 1)) {
                obj = obj->substructure(ctr);
                if (!obj)
                    break;
            }
            if (obj) {
                if ( auto off = obj->fieldOffset(*fieldOffset->debugPath.rbegin()); off) {
                    fieldOffset->off = *off;
                    done = true;
                }
            }
        }
        if (!done) {
            std::cerr << "no field " << fieldName << " found in " << typeName << " - defaulted to " << fieldOffset->off << "\n";
        }
    }
}

// Containers for offsets, as found in substructures of RootOffsets
// For each, we create an Offset object with appropriate container and field
// types for each offset. As we parse the JSON, we will populate the offsets as
// we find them in the process.
#define OFF(type, k, ...) Off<type> k{this, #k, {__VA_ARGS__}}
#define OFF_DEFAULT(type, k, dflt, ...) Off<type> k{this, #k, {__VA_ARGS__}, dflt}

struct RuntimeStateOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template<typename Field> using Off = Offset<_PyRuntimeState, Field>;
    OFF(PyThreadState *, finalizing, "_finalizing");
    OFF(PyInterpreterState *, interpreters_head, "interpreters", "head");
};


// Fields that come after PyTypeObject in PyHeapTypeObject
struct PyHeapTypeObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template<typename Field> using Off = Offset<PyHeapTypeObject, Field>;
    OFF(PyObject *, ht_slots);
    OFF(PyDictKeysObject *, ht_cached_keys);
};

struct PyObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyObject, Field>;
    OFF(PyTypeObject *, ob_type);
};

struct PyDictValuesOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyDictValues, Field>;
    OFF(uint8_t, capacity);
    OFF(uint8_t, size);
    OFF(uint8_t, embedded);
    OFF(uint8_t, valid);
    OFF(PyObject *, values);
};

struct PyDictKeysOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyDictKeysObject, Field>;
    OFF(ssize_t, dk_refcnt);
    OFF(uint8_t, dk_log2_size);
    OFF(uint8_t, dk_log2_index_bytes);
    OFF(uint8_t, dk_kind);
    OFF(uint32_t, dk_version);
    OFF(ssize_t, dk_usable);
    OFF(ssize_t, dk_nentries);
    OFF(char, dk_indices);
};

struct InterpreterStateOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyInterpreterState, Field>;
    OFF(int64_t, id);
    OFF(PyInterpreterState*, next);
    OFF(PyThreadState*, threads_head, "threads", "head");
    OFF(PyThreadState*, threads_main);
    OFF(_gc_runtime_state, gc);
    OFF(PyObject *, imports_modules, "imports", "modules");
    OFF(PyObject *, sysdict);
    OFF(PyObject *, builtins);
    OFF(_gil_runtime_state *, ceval_gil, "ceval", "gil");
    OFF(_gil_runtime_state, gil_runtime_state, "_gil");
    OFF(int, gil_runtime_state_locked, "_gil", "locked");
    OFF(void *, gil_runtime_state_enabled); // XXX: this is not an offset.
    OFF(PyThreadState *, gil_runtime_state_holder, "_gil", "last_holder");
    OFF(uint64_t, code_object_generation);
    OFF(uint64_t, tlbc_generation); // XXX: not an offset.
};

struct PyTypeObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyTypeObject, Field>;
    OFF(char *, tp_name);
    OFF(void *, tp_repr);
    OFF(unsigned long, tp_flags);
    OFF(ssize_t, tp_dictoffset);
    OFF(PyObject *, tp_dict);
    OFF(ssize_t, tp_basicsize);
};

struct ThreadStateOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyThreadState, Field>;
    OFF(PyThreadState *, prev);
    OFF(PyThreadState *, next);
    OFF(PyInterpreterState *, interp);
    OFF(_PyInterpreterFrame *, current_frame);
    // CPython 3.12 reaches the current interpreter frame through this
    // pointer; 3.14 stores it directly in PyThreadState.
    OFF(_PyCFrame *, cframe);
    OFF(unsigned long, thread_id);
    OFF(unsigned long, native_thread_id);
    OFF(_PyStackChunk *, datastack_chunk);
    OFF(unsigned int, status, "_status");
};

struct CFrameOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<_PyCFrame, Field>;
    // _PyCFrame is deliberately very small and its first field has remained
    // current_frame.  The default supports JSON files produced before
    // mkpyoff started emitting this otherwise private type.
    OFF_DEFAULT(_PyInterpreterFrame *, current_frame, 0);
};

struct InterpreterFrameOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<_PyInterpreterFrame, Field>;
    OFF(_PyInterpreterFrame *, previous);
    OFF(PyObject *, executable, "f_executable", "bits");
    OFF(PyObject *, f_code);
    OFF(char *, instr_ptr); // actually, _Py_CODEUNIT *, but line tables etc treat offsets as character pointers.
    OFF(char *, prev_instr); // actually, _Py_CODEUNIT *, but line tables etc treat offsets as character pointers.
    OFF(_PyStackRef, localsplus);
    OFF(char, owner);
    OFF(_PyStackRef *, stackpointer);
    OFF(int, stacktop);
    OFF(void *, tlbc_index); // XXX?
};

struct CodeObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyCodeObject, Field>;
    OFF(PyObject *, filename, "co_filename");
    OFF(PyUnicodeObject *, name, "co_name");
    OFF(PyObject *, qualname, "co_qualname");
    OFF(PyBytesObject *, linetable, "co_linetable");
    OFF(int, firstlineno, "co_firstlineno");
    OFF(int, argcount, "co_argcount");
    OFF(PyTupleObject *, localsplusnames, "co_localsplusnames");
    OFF(PyObject *, localspluskinds, "co_localspluskinds");
    OFF(char, co_code_adaptive, "co_code_adaptive");
    OFF(void, co_tlbc); // XXX?
};

struct PyBytesObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyBytesObject, Field>;
    OFF(ssize_t, ob_size, "ob_base", "ob_size");
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
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyUnicodeObject, Field>;
    OFF(ssize_t, asciiobject_size, "_base", "utf8_length");
    OFF(PyASCIIState, state, "_base", "_base", "state");
    OFF(ssize_t, length, "_base", "_base", "length");
};

struct PyTupleObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyTupleObject, Field>;
    OFF(PyObject *, ob_item);
    OFF(ssize_t, ob_size, "ob_base", "ob_size");
};

struct PyLongObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyLongObject, Field>;
    OFF(uintptr_t, lv_tag, "long_value", "lv_tag");
    OFF(unsigned int, ob_digit, "long_value", "ob_digit");
};

struct PyListObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyListObject, Field>;
    OFF(ssize_t, ob_size, "ob_base", "ob_size");
    OFF(PyObject **, ob_item);
};

struct PyDictObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template <typename Field> using Off = Offset<PyDictObject, Field>;
    OFF(PyDictKeysObject *, ma_keys);
    OFF(PyDictValues *, ma_values);  // Changed to PyDictValues* in Python 3.11+
};

struct PyMemberDescrObjectOffsets : OffsetContainer {
    using OffsetContainer::OffsetContainer;
    template<typename Field> using Off = Offset<PyMemberDescrObject, Field>;
    OFF(PyMemberDef *, d_member );
};

struct RootOffsets {
    std::unique_ptr<Structure> topLevel;
    uint64_t free_threaded;
    RuntimeStateOffsets runtime_state;
    InterpreterStateOffsets interpreter_state;
    ThreadStateOffsets thread_state;
    CFrameOffsets cframe;
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
    PyDictKeysOffsets dict_keys;
    PyDictValuesOffsets dict_values;
    PyHeapTypeObjectOffsets heap_type_object;
    PyMemberDescrObjectOffsets member_descr;
    RootOffsets(uint64_t version, Reader::csptr io, uintptr_t object);
    ~RootOffsets();
};

RootOffsets::RootOffsets(uint64_t versionExpected, Reader::csptr io, uintptr_t object)
    : runtime_state( "_PyRuntimeState", "runtime_state" )
      , interpreter_state( "PyInterpreterState", "interpreter_state" )
      , thread_state( "PyThreadState", "thread_state" )
      , cframe( "_PyCFrame", nullptr )
      , interpreter_frame( "_PyInterpreterFrame", "interpreter_frame" )
      , code_object( "PyCodeObject", "code_object" )
      , unicode_object( "PyUnicodeObject", "unicode_object" )
      , pyobject( "PyObject", "pyobject" )
      , tuple_object( "PyTupleObject", "tuple_object" )
      , type_object( "PyTypeObject", "type_object" )
      , long_object( "PyLongObject", "long_object" )
      , list_object( "PyListObject", "list_object" )
      , bytes_object( "PyBytesObject", "bytes_object" )
      , dict_object( "PyDictObject", "dict_object" )
      , dict_keys( "PyDictKeysObject", nullptr )
      , dict_values( "PyDictValues", nullptr )
      , heap_type_object( "PyHeapTypeObject", nullptr )
      , member_descr( "PyMemberDescrObject", nullptr )

{
    std::array<char, 16> chars;
    auto [ end, ec ] = std::to_chars(chars.begin(), chars.end(), versionExpected, 16);
    std::string name = std::string(chars.begin(), end) + ".json";
    std::ifstream in(name);
    if (!in.good()) {
        throw (Exception() << "cannot open '" << name << "'");
    }

    topLevel = parseContainer( in );
    Structure *pyDebugOffsets;
    if (auto debugOffsetsI = topLevel->fields.find("_Py_DebugOffsets"); debugOffsetsI != topLevel->fields.end()) {
        pyDebugOffsets = std::get<std::unique_ptr<Structure>>( debugOffsetsI->second ).get();
    } else {
        pyDebugOffsets = nullptr;
    }

    runtime_state.populate( topLevel.get(), pyDebugOffsets, io, object);
    interpreter_state.populate( topLevel.get(), pyDebugOffsets, io, object);
    thread_state.populate( topLevel.get(), pyDebugOffsets, io, object);
    cframe.populate( topLevel.get(), pyDebugOffsets, io, object);
    interpreter_frame.populate( topLevel.get(), pyDebugOffsets, io, object);
    code_object.populate( topLevel.get(), pyDebugOffsets, io, object);
    unicode_object.populate( topLevel.get(), pyDebugOffsets, io, object);
    pyobject.populate( topLevel.get(), pyDebugOffsets, io, object);
    tuple_object.populate( topLevel.get(), pyDebugOffsets, io, object);
    type_object.populate( topLevel.get(), pyDebugOffsets, io, object);
    long_object.populate( topLevel.get(), pyDebugOffsets, io, object);
    list_object.populate( topLevel.get(), pyDebugOffsets, io, object);
    bytes_object.populate( topLevel.get(), pyDebugOffsets, io, object);
    dict_object.populate( topLevel.get(), pyDebugOffsets, io, object);
    dict_keys.populate( topLevel.get(), pyDebugOffsets, io, object);
    dict_values.populate( topLevel.get(), pyDebugOffsets, io, object);
    heap_type_object.populate( topLevel.get(), pyDebugOffsets, io, object);
    member_descr.populate( topLevel.get(), pyDebugOffsets, io, object);

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

// Walk dict entries and call visitor for each key/value pair.
// Handles both combined dicts (keys/values in same entry) and split dicts
// (values in separate PyDictValues array). Also handles unicode-keyed dicts
// vs general dicts with different entry layouts.
template<typename Visitor>
void
Target::walkDictEntries(Remote<PyDictKeysObject *> keys_remote, Remote<PyDictValues *> values, Visitor visitor) const {

    auto scanDictEntries = [&]( auto &entries ) {
        auto nentries = fetch(offsets->dict_keys.dk_nentries(keys_remote));
        auto localEntries = fetchArray( entries, nentries );
        unsigned i = -1;
        for (auto entry : localEntries ) {
            ++i;
            intptr_t entryInt = reinterpret_cast<intptr_t>(entry.me_key);
            // Skip DKIX_{EMPTY,DUMMY,ERROR,KEY_CHANGED,....}
            if (entryInt < 0 && entryInt > -16)
                continue;

            PyObject *value_ptr;
            if (values) {
                // Split dict or inline values: values are in separate array
                uintptr_t values_array_addr = reinterpret_cast<uintptr_t>(values.remote) + offsets->dict_values.values.off;
                auto values_array = Remote<PyObject **>{reinterpret_cast<PyObject **>(values_array_addr)};
                value_ptr = fetch(Remote<PyObject **>{values_array.remote + i}).remote;
            } else {
                // Combined dict: value is in the entry
                value_ptr = entry.me_value;
            }

            visitor(Remote<PyObject *>{entry.me_key}, Remote<PyObject *>{value_ptr});
        }
    };
    // Dispatch based on key kind (unicode vs general)
    uintptr_t keys_addr = reinterpret_cast<uintptr_t>(keys_remote.remote);
    // dk_log2_index_bytes describes the full compact-index table, not the
    // size of one index.  In particular, the small shared-key tables used by
    // 3.12 instances reserve eight bytes even when dk_log2_size is zero.
    uintptr_t entries_addr = keys_addr + offsets->dict_keys.size
        + (size_t(1) << fetch(offsets->dict_keys.dk_log2_index_bytes(keys_remote)));
    auto kind = fetch(offsets->dict_keys.dk_kind(keys_remote));
    if (kind == DICT_KEYS_UNICODE || kind == DICT_KEYS_SPLIT) {
        auto entries = Remote<PyDictUnicodeEntry *>{reinterpret_cast<PyDictUnicodeEntry *>(entries_addr)};
        scanDictEntries(entries);
    } else {
        auto entries = Remote<PyDictKeyEntry *>{reinterpret_cast<PyDictKeyEntry *>(entries_addr)};
        scanDictEntries(entries);
    }
}

void
Target::dumpKeyValues(std::ostream &os, Remote<PyDictKeysObject *> keys_remote, Remote<PyDictValues *> values) const {
    const char *sep = "";
    walkDictEntries(keys_remote, values, [&](Remote<PyObject *>key, Remote<PyObject *>value) {
        os << sep << str(key) << ": " << str(value);
        sep = ", ";
    });
}

void
Target::dump(std::ostream &os, const Remote<PyDictObject *> &dictobj) const {
    dumpKeyValues(os,
                     fetch(offsets->dict_object.ma_keys(dictobj)),
                     fetch(offsets->dict_object.ma_values(dictobj))
                     );
}

// Dump __slots__ attributes for a Python object with slotted attributes.
// Reads ht_slots tuple from PyHeapTypeObject, looks up member descriptors in tp_dict,
// and prints each slot name with its value from the object.
void
Target::dumpSlots(std::ostream &os, Remote<PyTypeObject *> type, const Remote<PyObject *> &obj) const {
    // For slotted classes, get ht_slots from PyHeapTypeObject
    auto heaptype = type.reinterpretCast<PyHeapTypeObject *>();

    auto ht_slots = fetch( offsets->heap_type_object.ht_slots( heaptype ) );

    // ht_slots is a tuple of slot names
    auto slots_tuple = cast(types->pyTuple_Type, ht_slots );
    if (!slots_tuple)
        return;

    auto ob_size = fetch(offsets->tuple_object.ob_size(slots_tuple));
    if (ob_size == 0)
        return;

    // Get tp_dict to look up the member descriptors
    auto tp_dict_obj = fetch(offsets->type_object.tp_dict(type));
    if (!tp_dict_obj.remote)
        return;
    auto dict = tp_dict_obj.reinterpretCast<PyDictObject *>();
    auto slot_names = fetchArray(offsets->tuple_object.ob_item(slots_tuple), ob_size);
    auto ma_keys = fetch(offsets->dict_object.ma_keys(dict));
    auto ma_values = fetch(offsets->dict_object.ma_values(dict));

    const char *sep = "";
    os << " ";

    for (auto &slot_name : slot_names) {
        if (!slot_name)
            continue;

        // Look up this slot name in tp_dict to get the member descriptor
        Remote<PyMemberDef *> member_def_ptr { nullptr };
        walkDictEntries(ma_keys, ma_values, [&](Remote<PyObject *>key, Remote<PyObject *>value) {
            if (key == slot_name && value) {
                auto descr = value.reinterpretCast<PyMemberDescrObject*>();
                member_def_ptr = fetch( offsets->member_descr.d_member( descr ) );
            }
        });

        if (!member_def_ptr)
            continue;

        PyMemberDef member_def = fetch(Remote<PyMemberDef *>{member_def_ptr});

        // Manually calculate pointer to member from the offset.
        uintptr_t obj_addr = reinterpret_cast<uintptr_t>(obj.remote);
        auto slot_value_addr = Remote{reinterpret_cast<PyObject **>(obj_addr + member_def.offset)};
        auto slot_value_ptr = fetch(slot_value_addr);

        os << sep;
        dump(os, slot_name);
        os << ": ";
        if (slot_value_ptr) {
            dump(os, slot_value_ptr);
        } else {
            os << "(unset)";
        }
        sep = ", ";
    }
}

// Dump a user-defined Python object.
// Handles managed dicts (Python 3.11+), inline values (Python 3.13+),
// regular dicts, and __slots__-based objects.
void
Target::dumpUserDefined(std::ostream &os, const Remote<PyObject *> &remote) const {
    // User-defined type or other type
    auto type = pyType(remote);
    auto heapType = type.reinterpretCast<PyHeapTypeObject *>();

    os << "<";
    dump(os, fetch(offsets->type_object.tp_name(type)));
    os << " object> ";

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
            auto dict_addr = Remote{reinterpret_cast<PyObject **>(instance_addr + MANAGED_DICT_OFFSET)};
            auto dict_ptr = fetch(dict_addr);
            if (dict_ptr) {
                dump(os, dict_ptr);
            } else {
                auto cached_keys = fetch( offsets->heap_type_object.ht_cached_keys( heapType ) );

                if (cached_keys) {
                    auto tp_basic_size = fetch(offsets->type_object.tp_basicsize(type));
                    auto values = Remote<PyDictValues *>{reinterpret_cast<PyDictValues *>(instance_addr + tp_basic_size)};
                    dumpKeyValues(os, cached_keys, values);
                } else {
                    os << " {<no cached keys>}";
                }
            }
        } else {
            // Before 3.13, a managed instance dictionary can instead be a
            // tagged pointer to a split PyDictValues array.  Treating that
            // as a PyDictObject produces a plausible-looking, but invalid,
            // object address when printing Python 3.12 instances.
            auto dict_addr = Remote<PyObject **>{reinterpret_cast<PyObject **>(instance_addr + MANAGED_DICT_OFFSET)};
            auto dict_or_values = fetch(dict_addr);
            os << " ";
            if (reinterpret_cast<uintptr_t>(dict_or_values.remote) & 1) {
                    auto cached_keys = fetch(offsets->heap_type_object.ht_cached_keys(heapType));
                if (cached_keys) {
                    auto values = Remote<PyDictValues *>{reinterpret_cast<PyDictValues *>(
                        reinterpret_cast<uintptr_t>(dict_or_values.remote) + 1)};
                    dumpKeyValues(os, cached_keys, values);
                } else {
                    os << "{<no cached keys>}";
                }
            } else {
                dump(os, dict_or_values);
            }
        }
    } else if (dictoffset > 0) {
        uintptr_t instance_addr = reinterpret_cast<uintptr_t>(remote.remote);
        auto dict_addr = Remote<PyObject **>{reinterpret_cast<PyObject **>(instance_addr + dictoffset)};
        auto dict_ptr = fetch(dict_addr);
        dump(os, dict_ptr);
    } else {
        dumpSlots(os, type, remote);
    }
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

    unsigned long symVersion;
    try {
        auto versionAddr = proc_.resolveSymbol("Py_Version", false);
        symVersion = proc_.io->readObj<unsigned long>(versionAddr);
    }
    catch (const Exception &) {
        symVersion = 0x030c00f0;
    }

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

        unsigned long version;
        if (cookieInProc == Header::expectedCookie) {
            version = headerInProc.version;
        } else {
            *proc.context.debug << "bad cookie in " << sec.io()->filename() << ", no usable debugger protocol.\n";
            version = symVersion;
        }
        pyRuntime.remote = reinterpret_cast<_PyRuntimeState *>(secaddr);
        offsets = make_unique<RootOffsets>(version, proc.io, secaddr);
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
            Remote<_PyInterpreterFrame *> frame;
            if (threadOffs.current_frame.found()) {
                frame = fetch(threadOffs.current_frame(t));
            } else {
                auto cframe = fetch(threadOffs.cframe(t));
                if (cframe)
                    frame = fetch(offsets->cframe.current_frame(cframe));
            }
            while (frame) {
                Remote<PyObject *> executable;
                if (frameOffs.executable.found()) {
                    executable = fetch(frameOffs.executable(frame));
                    auto clear = (uintptr_t)executable.remote;
                    clear &= -8LL;
                    executable = { reinterpret_cast<PyObject *>(clear) };
                } else {
                    executable = fetch(frameOffs.f_code(frame));
                }
                auto code = cast(types->pyCode_Type, executable);
                if (code) {
                    auto name = fetch(offsets->code_object.name(code));
                    auto file = fetch(offsets->code_object.filename(code));
                    auto instr_ptr = frameOffs.instr_ptr.found()
                        ? fetch(frameOffs.instr_ptr(frame))
                        : fetch(frameOffs.prev_instr(frame));
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
                    os << "(non code frame " << typeName(pyType(executable)) << ")";
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
