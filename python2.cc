#include <python2.7/Python.h>
#include <python2.7/frameobject.h>
#include <python2.7/longintrepr.h>
#include "libpstack/python.h"
template<> std::set<const PythonTypePrinter<2> *> PythonTypePrinter<2>::all = std::set<const PythonTypePrinter<2> *>();
template<>
char PythonTypePrinter<2>::pyBytesType[] = "PyString_Type";

class BoolPrint : public PythonTypePrinter<2> {
    Elf::Addr print(const PythonPrinter<2> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto pio = (const PyIntObject *)pyo;
        pc->os << (pio->ob_ival ? "True" : "False");
        return 0;
    }
    const char *type() const override { return "PyBool_Type"; }
    bool dupdetect() const override { return false; }
};
static BoolPrint boolPrinter;

class ClassPrinter : public PythonTypePrinter<2> {
    Elf::Addr print(const PythonPrinter<2> *pc, const PyObject *po, const PyTypeObject *, Elf::Addr) const override {
        auto pco = reinterpret_cast<const PyClassObject *>(po);
        pc->os << "<class ";
        pc->print(intmax_t(pco->cl_name));
        pc->os << ">";
        return 0;
    };
    const char *type() const override { return "PyClass_Type"; }
    bool dupdetect() const override { return true; }
};
static ClassPrinter classPrinter;

class DictPrinter : public PythonTypePrinter<2> {
    Elf::Addr print(const PythonPrinter<2> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        PyDictObject *pdo = (PyDictObject *)pyo;
        if (pdo->ma_used == 0)
            return 0;
        for (Py_ssize_t i = 0; i < pdo->ma_mask ; ++i) {
            PyDictEntry pde = readPyObj<2, PyDictEntry>(*pc->proc.io, Elf::Addr(pdo->ma_table + i));
            if (pde.me_value == nullptr)
                continue;
            if (pde.me_key != nullptr) {
                pc->os << pc->prefix();
                pc->print(Elf::Addr(pde.me_key));
                pc->os << ": ";
                pc->print(Elf::Addr(pde.me_value));
                pc->os << "\n";
            }
        }
        return 0;
    }
    const char *type() const override { return "PyDict_Type"; }
    bool dupdetect() const override { return true; }
};
static DictPrinter dictPrinter;

class InstancePrinter : public PythonTypePrinter<2> {
    Elf::Addr print(const PythonPrinter<2> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        const auto pio = reinterpret_cast<const PyInstanceObject *>(pyo);
        pc->depth++;
        pc->os << "\n" << pc->prefix() << "class: ";
        pc->depth++;
        pc->print(Elf::Addr(pio->in_class));
        pc->depth--;
        pc->os << "\n" << pc->prefix() << "dict: \n";
        pc->depth++;
        pc->print(Elf::Addr(pio->in_dict));
        pc->depth--;
        pc->depth--;
        return 0;
    }
    const char *type() const override { return "PyInstance_Type"; }
    bool dupdetect() const override { return true; }
};
static InstancePrinter instancePrinter;

class IntPrint : public PythonTypePrinter<2> {
    Elf::Addr print(const PythonPrinter<2> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto pio = (const PyIntObject *)pyo;
        pc->os << pio->ob_ival;
        return 0;
    }
    const char *type() const override { return "PyInt_Type"; }
    bool dupdetect() const override { return false; }

};
static IntPrint intPrinter;

template<>
void PythonPrinter<2>::findInterpHeadFallback() {
    libpython = nullptr;
    for (auto &o : proc.objects) {
        std::string module = stringify(*o.second->io);
        if (module.find("python") == std::string::npos)
            continue;
        auto image = o.second;
        auto &syms = image->commonSections->debugSymbols;
        for (auto sym : syms) {
            if (sym.name.substr(0, 11) != "interp_head")
                continue;
            libpython = o.second;
            libpythonAddr = o.first;
            interp_head = libpythonAddr + sym.symbol.st_value;
            break;
        }
        if (interp_head)
            break;
    }
    if (libpython == nullptr)
        throw Exception() << "No libpython found";
    if (verbose)
       *debug << "python2 library is " << *libpython->io << std::endl;
}

#include "python.tcc"

template struct PythonPrinter<2>;
