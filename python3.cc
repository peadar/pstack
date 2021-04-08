#include <Python.h>
#include <frameobject.h>
#include <dictobject.h>
#include <longintrepr.h>
#include <longintrepr.h>
#include <unicodeobject.h>
#include "libpstack/python.h"

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

// class DictPrinter : public PythonTypePrinter<2> {
//     Elf::Addr print(const PythonPrinter<2> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
//         PyDictObject *pdo = (PyDictObject *)pyo;
//         if (pdo->ma_used == 0)
//             return 0;
        
//         if (pdo->ma_values == NULL) { //Combined table
//             for (Py_ssize_t i = 0; i < pdo->ma_used; ++i) {
//                 PyDictKeysObject key = readPyObj<3, PyDictKeysObject>(*pc->proc.io, Elf::Addr(pdo->ma_values + i));
//             }
//         } else { //Split table
//             for (Py_ssize_t i = 0; i < pdo->ma_used; ++i) {
//                 PyDictKeysObject key = readPyObj<3, PyDictKeysObject>(*pc->proc.io, Elf::Addr(pdo->ma_values + i));
//                 PyObject value = readPyObj<3, PyObject>(*pc->proc.io, Elf::Addr(pdo->ma_values + i));
//             }
//         }

//         for (Py_ssize_t i = 0; i < pdo->ma_used ; ++i) {
//         }
//         return 0;
//     }
//     const char *type() const override { return "PyDict_Type"; }
//     bool dupdetect() const override { return true; }
// };
// static DictPrinter dictPrinter;

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
