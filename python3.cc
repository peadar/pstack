#include <Python.h>
#include <frameobject.h>
#include <dictobject.h>
#include <Objects/dict-common.h>
#include <longintrepr.h>
#include <longintrepr.h>
#include <unicodeobject.h>
#include "libpstack/python.h"

#define DK_SIZE(dk) ((dk)->dk_size)
#define DK_IXSIZE(dk)                \
    (  DK_SIZE(dk) <= 0xff       ? 1 \
    :  DK_SIZE(dk) <= 0xffff     ? 2 \
    :  DK_SIZE(dk) <= 0xffffffff ? 4 \
                                 : sizeof(int64_t))
#define DK_ENTRIES(dk) \
    ((PyDictKeyEntry *)(&((int8_t *)((dk)->dk_indices))[DK_SIZE(dk) * DK_IXSIZE(dk)]))

template<> std::set<const PythonTypePrinter<3> *> PythonTypePrinter<3>::all = std::set<const PythonTypePrinter<3> *>();
template <>
char PythonTypePrinter<3>::pyBytesType[] = "PyUnicode_Type";

/**
 * @brief Converts a Python PyASCIIObject, PyCompactUnicodeObject or PyUnicodeObjec to a string
 * 
 * @param r The reader used
 * @param addr Address of the object
 * @return std::string 
 */
template <> std::string readString<3>(const Reader &r, const Elf::Addr addr) {
    PyASCIIObject baseObj = r.readObj<PyASCIIObject>(addr);
    int ascii = baseObj.state.ascii;
    int compact = baseObj.state.compact;
    int ready = baseObj.state.ready;

    if (compact && ascii && ready) {
        return r.readString(addr + sizeof(PyASCIIObject));
    } else if (compact & ready) {
        return r.readString(addr + sizeof(PyCompactUnicodeObject));
    } else {
       return r.readString(addr + offsetof(PyUnicodeObject, data));
    }
}

// Reads indexSize bytes at address as a signed int
int64_t readIndex(const Reader &r, const Elf::Addr addr, size_t indexSize) {
    char buf[8];
    r.read(addr, indexSize, buf);
    switch (indexSize) {
        case 1: return *(int8_t *)buf;
        case 2: return *(int16_t *)buf;
        case 4: return *(int32_t *)buf;
        case 8: return *(int64_t *)buf;
        default: throw Exception() << "Envalid dictionary size"; // Shouldn't happen
    }
}
class DictPrinter : public PythonTypePrinter<3> {
    Elf::Addr print(const PythonPrinter<3> *pc, const PyObject *object, const PyTypeObject *, Elf::Addr) const override {
        PyDictObject *dict = (PyDictObject *)object;
        if (dict->ma_used == 0)
            return 0;

        const PyDictKeysObject keys = readPyObj<3, PyDictKeysObject>(*pc->proc.io, Elf::Addr(dict->ma_keys));
        const size_t indexSize = DK_IXSIZE(&keys);
        const Elf::Addr keyEntries = Elf::Addr(dict->ma_keys) + offsetof(PyDictKeysObject, dk_indices) + (keys.dk_size * indexSize);

        const bool isSplit = dict->ma_values != NULL;

        PyObject* splitValues = NULL;

        if (isSplit)
            splitValues = readPyObj<3, PyObject*>(*pc->proc.io, Elf::Addr(dict->ma_values));
            
        pc->os << "{\n";
        pc->depth++;
        for (Py_ssize_t i = 0; i < keys.dk_size; ++i) {
            auto index = readIndex(*pc->proc.io, Elf::Addr(dict->ma_keys) + offsetof(PyDictKeysObject, dk_indices) + i * indexSize, indexSize);
            if (index == DKIX_EMPTY || index == DKIX_DUMMY) continue;

            PyDictKeyEntry keyEntry = readPyObj<3, PyDictKeyEntry>(*pc->proc.io, keyEntries + index * sizeof(PyDictKeyEntry));

            PyObject* value;
            if (isSplit)
                value = readPyObj<3, PyObject *>(*pc->proc.io, Elf::Addr(dict->ma_values) + index * sizeof(PyObject *));

            pc->os << pc->prefix();
            pc->print(Elf::Addr(keyEntry.me_key));
            pc->os << " : ";
            pc->print(isSplit ? Elf::Addr(value) : Elf::Addr(keyEntry.me_value));
            pc->os << "\n";
        }
        pc->depth--;
        pc->os << pc->prefix() << "}";
        return 0;
    }
    const char *type() const override { return "PyDict_Type"; }
    bool dupdetect() const override { return true; }
};
static DictPrinter dictPrinter;

class BoolPrinter : public PythonTypePrinter<3> {
    Elf::Addr print(const PythonPrinter<3> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto pio = (const _longobject *)pyo;
        pc->os << (pio->ob_digit[0] ? "True" : "False");
        return 0;
    }
    const char *type() const override { return "PyBool_Type"; }
    bool dupdetect() const override { return false; }
};

template <typename T, int pyv>  ssize_t
pyRefcnt(const T *o) {
   return o->ob_base.ob_refcnt;
}

template <int pyv, typename T>  const PyTypeObject *
pyObjtype(const T *o) {
   return o->ob_base.ob_type;
}


static BoolPrinter boolPrinter;

#include "python.tcc"

template struct PythonPrinter<3>;
