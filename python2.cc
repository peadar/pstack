#include <python2.7/Python.h>
#include <python2.7/frameobject.h>
#include <python2.7/longintrepr.h>
#include <python2.7/methodobject.h>
#include "libpstack/python.h"
#include "libpstack/stringify.h"
#include "libpstack/global.h"

namespace pstack {

template<> std::set<const PythonTypePrinter<2> *> PythonTypePrinter<2>::all = std::set<const PythonTypePrinter<2> *>();
template<> char PythonTypePrinter<2>::pyBytesType[] = "PyString_Type";

/**
 * @brief Reads a Python2 string
 * 
 * @param r The reader used
 * @param addr Address of PyStringObject
 * @return std::string 
 */
template <> std::string readString<2>(const Reader &r, const Elf::Addr addr) {
    return r.readString(addr + offsetof(PyBytesObject, ob_sval));
}

namespace {
class BoolPrint final : public PythonTypePrinter<2> {
    Elf::Addr print(const PythonPrinter<2> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto pio = (const PyIntObject *)pyo;
        pc->os << (pio->ob_ival ? "True" : "False");
        return 0;
    }
    const char *type() const override { return "PyBool_Type"; }
    bool dupdetect() const override { return false; }
};
static BoolPrint boolPrinter;

class ClassPrinter final : public PythonTypePrinter<2> {
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

class DictPrinter final : public PythonTypePrinter<2> {
    Elf::Addr print(const PythonPrinter<2> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        PyDictObject *pdo = (PyDictObject *)pyo;
        if (pdo->ma_used == 0) {
            pc->os << "{}";
            return 0;
        }
        
        if (pc->depth > pc->proc.options.maxdepth) {
            pc->os << "{ ... }";
            return 0;
        }

        pc->os << "{\n";
        pc->depth++;
        for (Py_ssize_t i = 0; i < pdo->ma_mask ; ++i) {
            PyDictEntry pde = readPyObj<2, PyDictEntry>(*pc->proc.io, Elf::Addr(pdo->ma_table + i));
            if (pde.me_value == nullptr)
                continue;
            if (pde.me_key != nullptr) {
                pc->os << pc->prefix();
                pc->print(Elf::Addr(pde.me_key));
                pc->os << " : ";
                pc->print(Elf::Addr(pde.me_value));
                pc->os << "\n";
            }
        }
        pc->depth--;
        pc->os << pc->prefix() << "}";
        return 0;
    }
    const char *type() const override { return "PyDict_Type"; }
    bool dupdetect() const override { return true; }
};
static DictPrinter dictPrinter;

class InstancePrinter final : public PythonTypePrinter<2> {
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

class IntPrint final : public PythonTypePrinter<2> {
    Elf::Addr print(const PythonPrinter<2> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto pio = (const PyIntObject *)pyo;
        pc->os << pio->ob_ival;
        return 0;
    }
    const char *type() const override { return "PyInt_Type"; }
    bool dupdetect() const override { return false; }

};
static IntPrint intPrinter;

}
template <typename T, int pyv>
ssize_t
pyRefcnt(const T *o) {
   return o->ob_refcnt;
}

template <int pyv, typename T>  const PyTypeObject *
pyObjtype(const T *o) {
   return o->ob_type;
}

template <>
int getKwonlyArgCount<2>(const PyObject *) {
    return 0;
}

template <>
std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Addr>
getInterpHead<2>(const Procman::Process &proc) {
    for (auto &o : proc.objects) {
        std::string module = stringify(*o.second->io);
        if (module.find("python") == std::string::npos)
           continue;
        auto image = o.second;
        auto syms = image->debugSymbols();
        for (auto sym : *syms) {
            if (syms->name(sym).substr(0, 11) != "interp_head")
                continue;
            auto libpython = o.second;
            auto libpythonAddr = o.first;
            auto interpHead = libpythonAddr + sym.st_value;
            if (verbose)
                *debug << "python2 library is " << *libpython->io << std::endl;
            return std::make_tuple(libpython, libpythonAddr, interpHead);
        }
    }

    throw Exception() << "No libpython2 found";
}
}
#include "python.tcc"

namespace pstack {
template struct PythonPrinter<2>;
}
