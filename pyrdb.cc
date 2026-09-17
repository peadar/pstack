#ifdef WITH_PYRDB
#include "libpstack/pyrdb.h"
#include <fstream>
#include <string>
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

struct PyASCIIState {
    unsigned int interned : 2;
    unsigned int kind : 3;
    unsigned int compact : 1;
    unsigned int ascii : 1;
    unsigned int statically_allocated : 1;
};

struct PyTypes {
    Remote<PyTypeObject *> lookupTypeSymbol(const char *name);
    Target &target;
    PyTypes(Target &target_) : target(target_) { }
    PyType<PyLongObject> pyLong_Type {lookupTypeSymbol("PyLong_Type")};
    PyType<PyFloatObject> pyFloat_Type {lookupTypeSymbol("PyFloat_Type")};
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
    auto [sym, idx] = target.pyObj->findDynamicSymbol(name);
    if (idx == 0) {
        std::cerr << "no type for " << name << "\n";
    }
    return { (PyTypeObject *)(target.pyAddr + sym.st_value) };
}

RawOffset::RawOffset(OffsetContainer *container_, std::string_view name_,
        std::initializer_list<std::string_view> debugPath_) : off(-1) {
    container_->fields[name_] = this;
    debugPath = debugPath_;
    if (debugPath.empty()) {
        debugPath.push_back(name_);
    }
}

void
OffsetContainer::populate(Target &t) {
    auto top = t.offsetData.get();
    auto topDebugOffsets = t.debugOffsets;
    auto &reader = t.pyRuntimeReader;

    const Structure *typeObject = top->substructure(typeName);
    auto debugOffsets = topDebugOffsets && debugOffsetsField ? topDebugOffsets->substructure( debugOffsetsField ) : nullptr;

    bool haveSize = false;
    if (debugOffsets) {
        if ( auto sizei = debugOffsets->fields.find("size"); sizei != debugOffsets->fields.end()) {
            size = reader->readObj<size_t>(std::get<int>(sizei->second) );
            haveSize = true;
        }
    } else if (typeObject) {
        if ( auto sizei = typeObject->fields.find("<size>"); sizei != typeObject->fields.end()) {
            size = std::get<int>(sizei->second);
            haveSize = true;
        }
    }

    if (!haveSize) {
        std::cerr << "no size for " << typeName << "\n";
        return;
    }

    for (auto &[fieldName, fieldOffset] : fields) {
        if (debugOffsets) {
            auto offsetoffset = debugOffsets->fieldOffset(fieldName);
            if (offsetoffset) {
                fieldOffset->off = reader->readObj<size_t>(*offsetoffset);
                continue;
            }
        }
        // Fall back to DWARF data.
        const Structure *obj = typeObject;
        for (auto &ctr : fieldOffset->debugPath | std::views::take(fieldOffset->debugPath.size() - 1)) {
            if (!obj)
                break;
            obj = obj->substructure(ctr);
        }
        if (obj) {
            if ( auto off = obj->fieldOffset(*fieldOffset->debugPath.rbegin()); off)
                fieldOffset->off = *off;
        }
    }
}

// Containers for offsets, as found in substructures of RootOffsets
// For each, we create an Offset object with appropriate container and field
// types for each offset. We populate the offsets from the JSON data, either
// directly from the per-type recorded DWARF info, or indirectly from the
// debug_offsets field in the _PyRuntime debug offsets header.

#define SPLICE(a, b) a##b
#define TYPE(type, fieldName) struct SPLICE(type, __offsets) : OffsetContainer { \
    template<typename Field> using Off = Offset<type, Field>; \
    SPLICE(type, __offsets)(Target &t) : OffsetContainer(#type, fieldName) { \
        populate(t); \
    }

#define ENDTYPE() };
#define OFF(type, k, ...) Off<type> k{this, #k, {__VA_ARGS__}}

TYPE( _PyRuntimeState, "runtime_state" )
    OFF(PyThreadState *, finalizing, "_finalizing");
    OFF(PyInterpreterState *, interpreters_head, "interpreters", "head");
ENDTYPE()

TYPE( PyHeapTypeObject, nullptr )
    OFF(PyObject *, ht_slots);
    OFF(PyDictKeysObject *, ht_cached_keys);
ENDTYPE()

TYPE(PyObject, "pyobject")
    OFF(PyTypeObject *, ob_type);
ENDTYPE()

TYPE( PyDictValues, nullptr )
    OFF(uint8_t, capacity);
    OFF(uint8_t, size);
    OFF(uint8_t, embedded);
    OFF(uint8_t, valid);
    OFF(PyObject *, values);
ENDTYPE()

TYPE( PyDictKeysObject, nullptr )
    OFF(ssize_t, dk_refcnt);
    OFF(uint8_t, dk_log2_size);
    OFF(uint8_t, dk_log2_index_bytes);
    OFF(uint8_t, dk_kind);
    OFF(uint32_t, dk_version);
    OFF(ssize_t, dk_usable);
    OFF(ssize_t, dk_nentries);
    OFF(char, dk_indices);
ENDTYPE()

TYPE(PyInterpreterState, "interpreter_state")
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
ENDTYPE()

TYPE(PyTypeObject, "type_object" )
    OFF(char *, tp_name);
    OFF(void *, tp_repr);
    OFF(unsigned long, tp_flags);
    OFF(PyTypeObject *, tp_base);
    OFF(ssize_t, tp_dictoffset);
    OFF(PyObject *, tp_dict);
    OFF(ssize_t, tp_basicsize);
ENDTYPE()

TYPE(PyThreadState, "thread_state")
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
ENDTYPE()

TYPE(_PyCFrame, nullptr )
    // _PyCFrame is deliberately very small and its first field has remained
    // current_frame.  The default supports JSON files produced before
    // mkpyoff started emitting this otherwise private type.
    OFF(_PyInterpreterFrame *, current_frame);
ENDTYPE()

TYPE(_PyInterpreterFrame, "interpreter_frame" )
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
ENDTYPE()

TYPE(PyCodeObject, "code_object" )
    OFF(PyObject *, filename, "co_filename");
    OFF(PyUnicodeObject *, name, "co_name");
    OFF(PyObject *, qualname, "co_qualname");
    OFF(PyBytesObject *, linetable, "co_linetable");
    OFF(int, firstlineno, "co_firstlineno");
    OFF(int, argcount, "co_argcount");
    OFF(int, kwonlyargcount, "co_kwonlyargcount");
    OFF(PyTupleObject *, localsplusnames, "co_localsplusnames");
    OFF(PyObject *, localspluskinds, "co_localspluskinds");
    OFF(char, co_code_adaptive, "co_code_adaptive");
    OFF(void, co_tlbc); // XXX?
ENDTYPE()

TYPE(PyBytesObject, "bytes_object" )
    OFF(ssize_t, ob_size, "ob_base", "ob_size");
    OFF(unsigned char, ob_sval);
ENDTYPE()

TYPE( PyUnicodeObject, "unicode_object" )
    OFF(ssize_t, asciiobject_size, "_base", "utf8_length");
    OFF(PyASCIIState, state, "_base", "_base", "state");
    OFF(ssize_t, length, "_base", "_base", "length");
ENDTYPE()

TYPE( PyTupleObject, "tuple_object" )
    OFF(PyObject *, ob_item);
    OFF(ssize_t, ob_size, "ob_base", "ob_size");
ENDTYPE()

TYPE( PyLongObject, "long_object" )
    OFF(uintptr_t, lv_tag, "long_value", "lv_tag");
    OFF(unsigned int, ob_digit, "long_value", "ob_digit");
ENDTYPE()

TYPE( PyFloatObject, "float_object" )
    OFF(double, ob_fval);
ENDTYPE()

TYPE( PyListObject, "list_object" )
    OFF(ssize_t, ob_size, "ob_base", "ob_size");
    OFF(PyObject **, ob_item);
ENDTYPE()

TYPE( PyDictObject, "dict_object" )
    OFF(PyDictKeysObject *, ma_keys);
    OFF(PyDictValues *, ma_values);  // Changed to PyDictValues* in Python 3.11+
ENDTYPE()

TYPE( PyMemberDescrObject, nullptr)
    OFF(PyMemberDef *, d_member );
ENDTYPE()

struct RootOffsets {
    Target &target;
    uint64_t free_threaded{false};
    _PyRuntimeState__offsets runtime_state{target};
    PyInterpreterState__offsets interpreter_state {target};
    PyThreadState__offsets thread_state{target};
    _PyCFrame__offsets cframe{target};
    _PyInterpreterFrame__offsets interpreter_frame{target};
    PyCodeObject__offsets code_object{target};
    PyUnicodeObject__offsets unicode_object{target};
    PyObject__offsets pyobject {target};
    PyTupleObject__offsets tuple_object{target};
    PyLongObject__offsets long_object{target};
    PyFloatObject__offsets float_object{target};
    PyListObject__offsets  list_object{target};
    PyBytesObject__offsets bytes_object{target};
    PyDictObject__offsets dict_object{target};
    PyDictKeysObject__offsets dict_keys{target};
    PyDictValues__offsets dict_values{target};
    PyTypeObject__offsets type_object{target};
    PyHeapTypeObject__offsets heap_type_object{target};
    PyMemberDescrObject__offsets member_descr{target };
    RootOffsets(Target &target_) : target(target_) {
        if (target.debugOffsets) {
            if (auto freeThreadedOffset = target.debugOffsets->fieldOffset("free_threaded"))
                free_threaded = target.pyRuntimeReader->readObj<uint64_t>(*freeThreadedOffset);
        }
    }
    ~RootOffsets() = default;
};

OffsetContainer::OffsetContainer(const char *typeName, const char *debugOffsetsField)
    : typeName(typeName), debugOffsetsField(debugOffsetsField)
{
}

void
Target::repr(ReprStream &os, const Remote<char *> &charptr) const {
    os << proc.io->readString(reinterpret_cast<Elf::Addr>(charptr.remote), os.remaining());
}

void
Target::repr(ReprStream &os, const Remote<PyTupleObject *> &charptr) const {
    auto count = fetch(offsets->tuple_object.ob_size(charptr));
    os << "(";
    size_t shown = 0;
    auto items = offsets->tuple_object.ob_item(charptr);
    for (; os.remaining() && shown < size_t(count); ++shown) {
        if (shown)
            os << ", ";
        repr(os, fetch(Remote<PyObject **>{items.remote + shown}));
    }
    os << ")";
}

void
Target::repr(ReprStream &os, const Remote<PyListObject *> &listobj) const {
    auto count = fetch(offsets->list_object.ob_size(listobj));
    auto items = fetch(offsets->list_object.ob_item(listobj));
    os << "[";
    size_t shown = 0;
    for (; os.remaining() && shown < size_t(count); ++shown) {
        if (shown)
            os << ", ";
        repr(os, fetch(Remote<PyObject **>{items.remote + shown}));
    }
    os << "]";
}

// Walk dict entries and call visitor for each key/value pair.
// Handles both combined dicts (keys/values in same entry) and split dicts
// (values in separate PyDictValues array). Also handles unicode-keyed dicts
// vs general dicts with different entry layouts.
template<typename Visitor>
void
Target::walkDictEntries(Remote<PyDictKeysObject *> keys, Remote<PyDictValues *> values, Visitor visitor) const {
    auto scanDictEntries = [&]( auto &entries ) {
        auto nentries = fetch(offsets->dict_keys.dk_nentries(keys));
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
                auto values_array = Remote{reinterpret_cast<PyObject **>(values_array_addr)};
                value_ptr = fetch(Remote{values_array.remote + i}).remote;
            } else {
                // Combined dict: value is in the entry
                value_ptr = entry.me_value;
            }

            if (!visitor(Remote{entry.me_key}, Remote{value_ptr}))
               break;
        }
    };
    // Dispatch based on key kind (unicode vs general)
    uintptr_t keys_addr = reinterpret_cast<uintptr_t>(keys.remote);
    // dk_log2_index_bytes describes the full compact-index table, not the
    // size of one index.  In particular, the small shared-key tables used by
    // 3.12 instances reserve eight bytes even when dk_log2_size is zero.
    uintptr_t entries_addr = keys_addr + offsets->dict_keys.size
        + (size_t(1) << fetch(offsets->dict_keys.dk_log2_index_bytes(keys)));
    auto kind = fetch(offsets->dict_keys.dk_kind(keys));
    if (kind == DICT_KEYS_UNICODE || kind == DICT_KEYS_SPLIT) {
        auto entries = Remote{reinterpret_cast<PyDictUnicodeEntry *>(entries_addr)};
        scanDictEntries(entries);
    } else {
        auto entries = Remote{reinterpret_cast<PyDictKeyEntry *>(entries_addr)};
        scanDictEntries(entries);
    }
}

void
Target::dumpKeyValues(ReprStream &os, Remote<PyDictKeysObject *> keys, Remote<PyDictValues *> values) const {
    const char *sep = "";
    walkDictEntries(keys, values, [&](Remote<PyObject *>key, Remote<PyObject *>value) {
        os << sep;
        repr(os, key);
        os << ": ";
        repr(os, value);
        sep = ", ";
        return os.remaining() != 0;
    });
}

void
Target::repr(ReprStream &os, const Remote<PyDictObject *> &dictobj) const {
    os << "{";
    dumpKeyValues(os,
                     fetch(offsets->dict_object.ma_keys(dictobj)),
                     fetch(offsets->dict_object.ma_values(dictobj))
                     );
    os << "}";
}

// Dump __slots__ attributes for a Python object with slotted attributes.
// Each heap type's ht_slots contains only the slots it adds, so walk tp_base
// to include descriptors inherited from slotted base classes.
void
Target::dumpSlots(ReprStream &os, Remote<PyTypeObject *> type, const Remote<PyObject *> &obj) const {
    constexpr uintptr_t Py_TPFLAGS_HEAPTYPE = 1UL << 9;
    const char *sep = "";
    os << " {";

    for (; type; type = fetch(offsets->type_object.tp_base(type))) {
        // tp_base eventually reaches static types such as object, which do
        // not have a PyHeapTypeObject tail containing ht_slots.
        if (!(fetch(offsets->type_object.tp_flags(type)) & Py_TPFLAGS_HEAPTYPE))
            continue;

        auto heaptype = type.reinterpretCast<PyHeapTypeObject *>();
        auto ht_slots = fetch(offsets->heap_type_object.ht_slots(heaptype));
        auto slots_tuple = cast(types->pyTuple_Type, ht_slots);
        if (!slots_tuple)
            continue;

        auto ob_size = fetch(offsets->tuple_object.ob_size(slots_tuple));
        if (ob_size == 0)
            continue;

        auto tp_dict_obj = fetch(offsets->type_object.tp_dict(type));
        if (!tp_dict_obj)
            continue;
        auto dict = tp_dict_obj.reinterpretCast<PyDictObject *>();
        auto slot_names = fetchArray(offsets->tuple_object.ob_item(slots_tuple), ob_size);
        auto ma_keys = fetch(offsets->dict_object.ma_keys(dict));
        auto ma_values = fetch(offsets->dict_object.ma_values(dict));

        for (auto &slot_name : slot_names) {
            if (os.remaining() == 0)
                return;
            if (!slot_name)
                continue;

            // Look up this slot name in the declaring type's dictionary.
            Remote<PyMemberDef *> member_def_ptr { nullptr };
            walkDictEntries(ma_keys, ma_values, [&](Remote<PyObject *>key, Remote<PyObject *>value) {
                if (key == slot_name && value) {
                    auto descr = value.reinterpretCast<PyMemberDescrObject*>();
                    member_def_ptr = fetch(offsets->member_descr.d_member(descr));
                }
                return true;
            });

            if (!member_def_ptr)
                continue;

            PyMemberDef member_def = fetch(Remote<PyMemberDef *>{member_def_ptr});
            uintptr_t obj_addr = reinterpret_cast<uintptr_t>(obj.remote);
            auto slot_value_addr = Remote{reinterpret_cast<PyObject **>(obj_addr + member_def.offset)};
            auto slot_value_ptr = fetch(slot_value_addr);

            os << sep;
            repr(os, slot_name);
            os << ": ";
            if (slot_value_ptr) {
                repr(os, slot_value_ptr);
            } else {
                os << "(unset)";
            }
            sep = ", ";
        }
    }
    os << "}";
}

// Dump a user-defined Python object.
// Handles managed dicts (Python 3.11+), inline values (Python 3.13+),
// regular dicts, and __slots__-based objects.
void
Target::reprUserDefined(ReprStream &os, const Remote<PyObject *> &remote) const {
    auto type = pyType(remote);
    auto tp_flags = fetch(offsets->type_object.tp_flags(type));
    constexpr uintptr_t Py_TPFLAGS_HEAPTYPE = 1UL << 9;
    if (!(tp_flags & Py_TPFLAGS_HEAPTYPE)) {
        os << "unhandled type <";
        repr(os, fetch(offsets->type_object.tp_name(type)));
        os << ">";
        return;
    }

    auto heapType = type.reinterpretCast<PyHeapTypeObject *>();

    os << "<";
    repr(os, fetch(offsets->type_object.tp_name(type)));
    os << " object> ";

    // For user-defined types, try to get the instance dictionary
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
                repr(os, dict_ptr);
            } else {
                auto cached_keys = fetch( offsets->heap_type_object.ht_cached_keys( heapType ) );

                if (cached_keys) {
                    auto tp_basic_size = fetch(offsets->type_object.tp_basicsize(type));
                    auto values = Remote<PyDictValues *>{reinterpret_cast<PyDictValues *>(instance_addr + tp_basic_size)};
                    os << " {";
                    dumpKeyValues(os, cached_keys, values);
                    os << "}";
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
                    os << "{";
                    dumpKeyValues(os, cached_keys, values);
                    os << "}";
                } else {
                    os << "{<no cached keys>}";
                }
            } else {
                repr(os, dict_or_values);
            }
        }
    } else if (dictoffset > 0) {
        uintptr_t instance_addr = reinterpret_cast<uintptr_t>(remote.remote);
        auto dict_addr = Remote<PyObject **>{reinterpret_cast<PyObject **>(instance_addr + dictoffset)};
        auto dict_ptr = fetch(dict_addr);
        repr(os, dict_ptr);
    } else {
        dumpSlots(os, type, remote);
    }
}

void
Target::repr(ReprStream &os, const Remote<PyObject *> &remote) const {
    if (!remote) {
        os << "(null)";
        return;
    }
    auto address = reinterpret_cast<uintptr_t>(remote.remote);
    if (!os.buffer().begin(address)) {
        os << "<...>";
        return;
    }
    struct RenderingGuard {
        ReprStreamBuf &buffer;
        uintptr_t address;
        ~RenderingGuard() { buffer.end(address); }
    } guard{os.buffer(), address};
    if (auto v = cast(types->pyUnicode_Type, remote); v)
        repr(os, v);
    else if (auto v = cast(types->pyLong_Type, remote); v)
        repr(os, v);
    else if (auto v = cast(types->pyFloat_Type, remote); v)
        repr(os, v);
    else if (auto v = cast(types->pyTuple_Type, remote); v)
        repr(os, v);
    else if (auto v = cast(types->pyList_Type, remote); v)
        repr(os, v);
    else if (auto v = cast(types->pyBool_Type, remote); v)
        repr(os, v);
    else if (auto v = cast(types->pyBytes_Type, remote); v)
        repr(os, v);
    else if (auto v = cast(types->pyDict_Type, remote); v)
        repr(os, v);
    else if (auto v = cast(types->pyNone_Type, remote); v)
        os << "None";
    else
        reprUserDefined(os, remote);
}

#if 1 || __i386__ // there's no overload for "operator<<" for __uint128_t
using BIGINT = uint64_t;
#else
using BIGINT = __uint128_t;
#endif
constexpr size_t BIGINT_BITS = CHAR_BIT * sizeof (BIGINT);

void
Target::repr(ReprStream &os, const Remote<PyLongObject *> &remote) const {
    auto type = pyType(Remote<PyObject *>(reinterpret_cast<PyObject *>(remote.remote)));
    if (type == types->pyBool_Type.typeObject) {
        os << (fetch(offsets->long_object.ob_digit(remote)) ? "True" : "False");
    } else {
        auto tag = fetch(offsets->long_object.lv_tag(remote));
        // First 2 bits:
        //      0, 0b00 -> zero
        //      1, 0b01 -> positive
        //      2, 0b10 -> negative
        // Third bit indicates "compact" representation.
        auto digitCount = tag >> 3;
        auto digits = fetchArray(offsets->long_object.ob_digit(remote), digitCount);
        BIGINT big = 0;
        bool infinite = false;
        for (size_t i = 0; !infinite && i < digitCount; ++i) {
            // 30 bits per 32-bit "digit", to make arithmetic faster.
            // If we are more than 2 32-bit digits in, then we can't fit the value
            // in our 64-bit value.
            auto remaining_bits = BIGINT_BITS - (30 * i);
            if (remaining_bits < 30) {
                uint32_t mask = ~0UL << remaining_bits;
                if (digits[i] & mask) {
                    infinite = true;
                    break;
                }
            }
            big |= BIGINT(digits[i]) << (30 * i);
        }
        if ((tag & 0x3) == 2) {
            os << "-";
        }
        if (infinite)
            os << "<practical infinity>";
        else
            os << big;
    }
}

void
Target::repr(ReprStream &os, const Remote<PyFloatObject *> &remote) const {
    os << fetch(offsets->float_object.ob_fval(remote));
}

struct ReprChar { uint32_t c; char quote; };
std::ostream &
operator << (std::ostream &os, const ReprChar &e) {
    switch (e.c) {
    case '\\': return os << "\\\\";
    case '\n': return os << "\\n";
    case '\r': return os << "\\r";
    case '\t': return os << "\\t";
    case '\b': return os << "\\b";
    case '\f': return os << "\\f";
    }
    if (e.c == uint32_t(static_cast<unsigned char>(e.quote)))
        return os << '\\' << e.quote;
    if (e.c >= 32 && e.c < 127)
        return os << char(e.c);
    if (e.c <= 0xff)
        return os << "\\x" << std::setw(2) << std::setfill('0') << std::hex << e.c << std::dec;
    return os << UTF8(e.c);
}

void
Target::repr(ReprStream &os, const Remote<PyBytesObject *> &remote) const {
    auto sz = fetch(offsets->bytes_object.ob_size(remote));
    // Fetch only a bounded prefix.  Escaping can expand a byte, so account
    // for it while rendering rather than reserving a fixed character count.
    auto fetched = std::min<size_t>(sz, os.remaining());
    auto vec = fetchArray(offsets->bytes_object.ob_sval(remote), fetched);
    os << "b'";
    for (auto c : vec) {
        os << ReprChar{static_cast<unsigned char>(c), '\''};
        if (!os.remaining())
            break;
    }
    os << "'";
}

std::pair<std::string, bool>
Target::readUnicodeText(Remote<PyUnicodeObject *> remote, size_t maxbytes) const {
    const auto &unicode = offsets->unicode_object;
    auto state = fetch(unicode.state(remote));
    auto length = fetch(unicode.length(remote));
    auto objoff = uintptr_t(remote.remote);
    uintptr_t dataAddr;
    if (state.compact) {
        dataAddr = objoff + (state.ascii ? unicode.asciiobject_size.off : unicode.size - sizeof(uintptr_t));
    } else {
        auto dataAddrPtr = Remote<uintptr_t *>{reinterpret_cast<uintptr_t *>(objoff + unicode.size - sizeof(uintptr_t))};
        dataAddr = fetch(dataAddrPtr);
    }

    std::ostringstream text;
    size_t shown = 0;
    if (state.kind == 1) {
        shown = std::min<size_t>(length, maxbytes);
        auto data = fetchArray(Remote<char *>{reinterpret_cast<char *>(dataAddr)}, shown);
        text.write(data.data(), data.size());
    } else if (state.kind == 2) {
        shown = std::min<size_t>(length, maxbytes / sizeof(uint16_t));
        auto data = fetchArray(Remote<uint16_t *>{reinterpret_cast<uint16_t *>(dataAddr)}, shown);
        for (auto c : data)
            text << UTF8(c);
    } else if (state.kind == 4) {
        shown = std::min<size_t>(length, maxbytes / sizeof(uint32_t));
        auto data = fetchArray(Remote<uint32_t *>{reinterpret_cast<uint32_t *>(dataAddr)}, shown);
        for (auto c : data)
            text << UTF8(c);
    }
    return {text.str(), shown != size_t(length)};
}

void
Target::repr(ReprStream &os, const Remote<PyUnicodeObject *> &remote) const {
    const auto &unicode = offsets->unicode_object;
    auto state = fetch(unicode.state(remote));
    auto objoff = uintptr_t(remote.remote);
    auto length = fetch(unicode.length(remote));

    auto fetched = std::min<size_t>(length, os.remaining());
    auto append = [&](uint32_t c) {
        os << ReprChar{c, '\''};
        return os.remaining() != 0;
    };

    uintptr_t dataAddr;
    if (state.compact) {
        // Compact form. Data follows the object.
        dataAddr = objoff + (state.ascii ? unicode.asciiobject_size.off : unicode.size - sizeof (uintptr_t));
    } else {
        // non-compact form - data is pointed to by the pointer at the end of the PyUnicodeObject.
        Remote<uintptr_t *> dataAddrPtr;
        dataAddrPtr.remote = reinterpret_cast<uintptr_t *>(objoff + unicode.size - sizeof(uintptr_t));
        dataAddr = fetch(dataAddrPtr);
    }
    os << "'";
    switch (state.kind) {
        case 1: {
            Remote<char *> dataptr { reinterpret_cast<char *>(dataAddr) };
            std::vector<char> data;
            data = fetchArray(dataptr, fetched);
            for (auto c : data)
                if (!append(static_cast<unsigned char>(c)))
                    break;
            break;
        }
        case 2: {
            // data is 2-byte unicode. Convert to UTF-8
            Remote<uint16_t *> dataptr { reinterpret_cast<uint16_t *>(dataAddr) };
            std::vector<uint16_t> data;
            data = fetchArray(dataptr, fetched);
            for (auto c : data)
                if (!append(c))
                    break;
            break;
        }
        case 4: {
            // data is 4-byte unicode. Convert to UTF-8
            Remote<uint32_t *> dataptr { reinterpret_cast<uint32_t *>(dataAddr) };
            std::vector<uint32_t> data;
            data = fetchArray(dataptr, fetched);
            for (auto c : data)
                if (!append(c))
                    break;
            break;
        }
        default:
            os << "<string of unsupported kind " << state.kind << ">";
            break;
    }
    os << "'";
}

std::string
Target::typeName(Remote<PyTypeObject *> remote) const {
    return proc.io->readString((uintptr_t)fetch(offsets->type_object.tp_name(remote)).remote);
}

Remote<PyTypeObject *>
Target::pyType(Remote<PyObject *> remote) const {
    return fetch(offsets->pyobject.ob_type(remote));
}

std::ifstream
Target::findOffsetsFile(Version v) const {
   auto fn = v.offsetFileName();
   std::ifstream in;
   for (auto p : findXdgDataDirs()) {
      auto path = p/fn;
      in.open(path);
      if (in.good()) {
         if (proc.context.verbose) {
            *proc.context.debug << "found python offsets data in " << path << "\n";
         }
         return in;
      }
   }
   throw Exception() << "cannot find '" << fn << "' - try using pstack-mkpyoff?";
}

Target::Target(Procman::Process &proc_)
    : proc{proc_}
{
    // find a python interpreter. The first thing with the right section with the right contents will do.
    for (auto &[addr, mapped] : proc.objects) {
        auto obj = mapped.object(proc.context);
        if (!obj)
            continue;
        auto &sec = obj->getSection(".PyRuntime", SHT_PROGBITS);
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
        pyObj = obj;
        pyAddr = addr;
        types = std::make_unique<PyTypes>(*this);

        if (cookieInProc == Header::expectedCookie) {
            version = { headerInProc.version,  obj->getHeader().e_machine };
        } else {
            // See if we can find the Py_Version symbol as a fallback, for python
            // versions before the introduction of the remote debugger protocol
            auto [obj, loadaddr, sym] = proc_.resolveSymbolDetail("Py_Version", false);
            version = { proc_.io->readObj<unsigned long>(loadaddr + sym.st_value), obj->getHeader().e_machine };
        }
        pyRuntime.remote = reinterpret_cast<_PyRuntimeState *>(secaddr);
        pyRuntimeReader = proc.io->view("_PyRuntime", secaddr);
        auto offsetFile = findOffsetsFile(version);
        offsetData = parseContainer(offsetFile);
        if (auto debugOffsetsI = offsetData->fields.find("_Py_DebugOffsets"); debugOffsetsI != offsetData->fields.end()) {
            debugOffsets = std::get<std::unique_ptr<Structure>>( debugOffsetsI->second ).get();
        }
        offsets = std::make_unique<RootOffsets>( *this );
        break;
    }
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

const std::string_view pad(size_t sz) {
    sz *= 3;
    static const std::string spaces( 1024, ' ');
    return std::string_view( spaces.begin(), spaces.begin() + std::min(size_t(1024u), sz));
}

void Target::dumpAllInterpreters(std::ostream &os, size_t indent) const {
    Procman::StopProcess here(&proc);
    for (Remote<PyInterpreterState *> interp : interpreters()) {
        os << pad(indent) << "python interpreter @" << interp << "\n";
        dumpInterpreter(os, interp, indent + 1);

    }
}

void Target::dumpInterpreter( std::ostream &os, Remote<PyInterpreterState *> interp, size_t indent) const {
        for (Remote<PyThreadState *> t : threads(interp)) {
            dumpThread( os, t, indent);
            os << "\n";
        }
}

void Target::dumpThread(std::ostream &os, Remote<PyThreadState *> t, size_t indent) const {
    auto &threadOffs = offsets->thread_state;
    auto id = fetch(threadOffs.thread_id(t));
    auto native_id = fetch(threadOffs.native_thread_id(t));
    os << pad(indent) << "thread: " << (void *)id << ", lwp: " << native_id << "\n";
    Remote<_PyInterpreterFrame *> frame;
    if (threadOffs.current_frame.found()) {
        frame = fetch(threadOffs.current_frame(t));
    } else {
        Remote<_PyCFrame *> cframe = fetch(threadOffs.cframe(t));
        if (cframe)
            frame = fetch(offsets->cframe.current_frame(cframe));
    }
    while (frame) {
        dumpFrame( os, frame, indent + 1);
        frame = fetch(offsets->interpreter_frame.previous(frame));
    }
}

void Target::dumpFrame(std::ostream &os, Remote<_PyInterpreterFrame *> frame, size_t indent) const {
    Remote<PyObject *> executable;
    auto &frameOffs = offsets->interpreter_frame;
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
        auto [functionName, nameTruncated] = readUnicodeText(name, 1024);
        if (nameTruncated)
            functionName += "...";
        os << pad(indent) << functionName;
        if (proc.context.options.doargs || proc.context.options.dolocals) {
            auto lnames = fetch(offsets->code_object.localsplusnames(code));
            auto localCount = fetch(offsets->tuple_object.ob_size(lnames));
            auto nameVec = fetchArray(offsets->tuple_object.ob_item(lnames), localCount);
            auto valueVec = fetchArray(offsets->interpreter_frame.localsplus(frame), localCount);
            auto argCount = fetch(offsets->code_object.argcount(code));
            auto kwonlyArgCount = fetch(offsets->code_object.kwonlyargcount(code));

            auto printValue = [&](Remote<PyObject *> value) {
                auto intv = intptr_t( value.remote );
                if ((intv & 3) == 3) {
                    os << (intv >> 2);
                } else {
                    ReprStreamBuf buffer(os.rdbuf());
                    ReprStream limited(buffer, proc.context.options.maxstr);
                    value.remote = reinterpret_cast<PyObject *>(intv & ~3 );
                    if (proc.context.verbose > 1)
                       os << value << ":";
                    repr(limited, value);
                    if (limited.remaining() == 0)
                        os << "...";
                }
            };

            if (proc.context.options.doargs) {
                os << "(";
                for (int i = 0; i < argCount; ++i) {
                    if (i)
                        os << ", ";
                    if (proc.context.verbose) {
                       auto [varName, nameTruncated] = readUnicodeText(cast(types->pyUnicode_Type, nameVec[i]), 1024);
                       os << varName << "=";
                    }
                    printValue(valueVec[i]);
                }
                for (int i = 0; i < kwonlyArgCount; ++i) {
                    if (argCount || i)
                        os << ", ";
                    auto argIndex = argCount + i;
                    auto [varName, nameTruncated] = readUnicodeText(cast(types->pyUnicode_Type, nameVec[argIndex]), 1024);
                    os << varName << "=";
                    printValue(valueVec[argIndex]);
                }
                os << ")";
            }

            auto [filename, fileTruncated] = readUnicodeText(cast(types->pyUnicode_Type, file), 4096);
            if (fileTruncated)
                filename += "...";
            os << " in " << filename << ":" << line;
            if (proc.context.options.dolocals) {
                os << "\n";
                for (ssize_t i = argCount + kwonlyArgCount; i < localCount; ++i) {
                    auto name = nameVec[i];
                    auto value = valueVec[i];
                    os << pad(indent+1);
                    printValue(name);
                    os << ": ";
                    printValue(value);
                    os << "\n";
                }
            }
        } else {
            auto [filename, fileTruncated] = readUnicodeText(cast(types->pyUnicode_Type, file), 4096);
            if (fileTruncated)
                filename += "...";
            os << " in " << filename << ":" << line;
        }
    } else {
        os << "(non code frame " << typeName(pyType(executable)) << ")";
    }
    os << "\n";
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
#endif
