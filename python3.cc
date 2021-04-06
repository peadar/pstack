#include <python3.7/Python.h>
#include <python3.7/frameobject.h>
#include <python3.7/longintrepr.h>
#include <python3.7/longintrepr.h>
#include <python3.7/unicodeobject.h>
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

class BoolPrinter : public PythonTypePrinter<3> {
    Elf::Addr print(const PythonPrinter<3> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto pio = (const _longobject *)pyo;
        pc->os << (pio->ob_digit[0] ? "True" : "False");
        return 0;
    }
    const char *type() const override { return "PyBool_Type"; }
    bool dupdetect() const override { return false; }
};
static BoolPrinter boolPrinter;

#include "python.tcc"

template struct PythonPrinter<3>;
