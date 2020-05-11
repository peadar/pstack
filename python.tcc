#include <iostream>
#include <algorithm>
#include <stdlib.h>
#include <stddef.h>

#include "libpstack/dwarf.h"

// This reimplements PyCode_Addr2Line
template<int PyV> int
getLine(const Reader &proc, const PyCodeObject *code, const PyFrameObject *frame)
{
    auto lnotab = readPyObj<PyV, PyVarObject>(proc, Elf::Addr(code->co_lnotab));

    unsigned char linedata[lnotab.ob_size];
    proc.readObj(Elf::Addr(code->co_lnotab) + offsetof(PyBytesObject, ob_sval),
            &linedata[0], lnotab.ob_size);
    int line = code->co_firstlineno;
    int addr = 0;
    unsigned char *p = linedata;
    unsigned char *e = linedata + lnotab.ob_size;
    while (p < e) {
        addr += *p++;
        if (addr > frame->f_lasti) {
            break;
        }
        line += *p++;
    }
    return line;
}

template <int PyV> class HeapPrinter : public PythonTypePrinter<PyV> {
    Elf::Addr print(const PythonPrinter<PyV> *pc, const PyObject *, const PyTypeObject *pto, Elf::Addr remote) const override {
        pc->os << pc->proc.io->readString(Elf::Addr(pto->tp_name));
        if (pto->tp_dictoffset > 0) {
            pc->os << "\n";
            pc->depth++;
            PyObject *dictAddr;
            pc->proc.io->readObj(remote + pto->tp_dictoffset, &dictAddr);
            pc->print(Elf::Addr(dictAddr));
            pc->depth--;
            pc->os << "\n";
        }
        return 0;
    }
    const char *type() const override { return nullptr; }
    bool dupdetect() const override { return true; }
};

template <int PyV> class StringPrinter : public PythonTypePrinter<PyV> {
    Elf::Addr print(const PythonPrinter<PyV> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto *pso = (const PyBytesObject *)pyo;
        pc->os << "\"" << pso->ob_sval << "\"";
        return 0;
    }
    const char *type() const override { return PythonTypePrinter<PyV>::pyBytesType; }
    bool dupdetect() const override { return false; }
};

template <int PyV> class FloatPrinter : public PythonTypePrinter<PyV> {
    Elf::Addr print(const PythonPrinter<PyV> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto *pfo = (const PyFloatObject *)pyo;
        pc->os << pfo->ob_fval;
        return 0;
    }
    const char *type() const override { return "PyFloat_Type"; }
    bool dupdetect() const override { return false; }
};

template<int PyV> class ModulePrinter : public PythonTypePrinter<PyV> {
    Elf::Addr print(const PythonPrinter<PyV> *pc, const PyObject *, const PyTypeObject *, Elf::Addr) const override {
        pc->os << "<python module>";
        return 0;
    }
    const char *type() const override { return "PyModule_Type"; }
};

template<int PyV> class ListPrinter : public PythonTypePrinter<PyV> {
    Elf::Addr print(const PythonPrinter<PyV> *pc, const PyObject *po, const PyTypeObject *, Elf::Addr) const override {
        auto plo = reinterpret_cast<const PyListObject *>(po);
        pc->os << "list: \n";
        auto size = std::min(((PyVarObject *)plo)->ob_size, Py_ssize_t(100));
        PyObject *objects[size];
        pc->proc.io->readObj(Elf::Addr(plo->ob_item), &objects[0], size);
        pc->depth++;
        for (auto addr : objects) {
          pc->os << pc->prefix();
          pc->print(Elf::Addr(addr));
          pc->os << "\n";
        }
        pc->depth--;
        pc->os << "\n";
        return 0;
    }
    const char *type() const override { return "PyList_Type"; }
    bool dupdetect() const override { return true; }
};

template <int PyV> class TypePrinter : public PythonTypePrinter<PyV> {
    Elf::Addr print(const PythonPrinter<PyV> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto pto = (const _typeobject *)pyo;
        pc->os << "type :\"" << pc->proc.io->readString(Elf::Addr(pto->tp_name)) << "\"";
        return 0;
    }
    const char *type() const override { return "PyType_Type"; }
    bool dupdetect() const override { return true; }
};

template <int PyV> class LongPrinter : public PythonTypePrinter<PyV> {
    Elf::Addr print(const PythonPrinter<PyV> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr) const override {
        auto plo = (PyLongObject *)pyo;
        intmax_t value = 0;
        for (int i = 0; i < ((PyVarObject *)plo)->ob_size; ++i) {
            value += intmax_t(plo->ob_digit[i]) << (PyLong_SHIFT * i) ;
        }
        pc->os << value;
        return 0;
    }
    const char *type() const override {
        return "PyLong_Type";
    }
    bool dupdetect() const override { return false; }
};

template <int PyV>
int
printTupleVars(const PythonPrinter<PyV> *pc, Elf::Addr namesAddr, Elf::Addr valuesAddr, const char *type, Py_ssize_t maxvals = 1000000)
{
    const auto &names = readPyObj<PyV, PyTupleObject>(*pc->proc.io, namesAddr);

    maxvals = std::min(((PyVarObject *)&names)->ob_size, maxvals);
    if (maxvals == 0)
        return 0;

    std::vector<PyObject *> varnames(maxvals);
    std::vector<PyObject *> varvals(maxvals);

    pc->proc.io->readObj(namesAddr + offsetof(PyTupleObject, ob_item), &varnames[0], maxvals);
    pc->proc.io->readObj(valuesAddr, &varvals[0], maxvals);

    pc->os << pc->prefix() << type <<":" << std::endl;
    pc->depth++;
    for (auto i = 0; i < maxvals; ++i) {
        pc->os << pc->prefix();
        pc->print(Elf::Addr(varnames[i]));
        pc->os << "=";
        pc->print(Elf::Addr(varvals[i]));
        pc->os << "\n";
    }
    pc->depth--;
    return maxvals;

}

template <int PyV> class FramePrinter : public PythonTypePrinter<PyV> {
    Elf::Addr print(const PythonPrinter<PyV> *pc, const PyObject *pyo, const PyTypeObject *, Elf::Addr remoteAddr) const override {
        auto pfo = (const PyFrameObject *)pyo;
        if (pfo->f_code != 0) {
            const auto &code = readPyObj<PyV, PyCodeObject>(*pc->proc.io, Elf::Addr(pfo->f_code));
            auto lineNo = getLine<PyV>(*pc->proc.io, &code, pfo);
            auto func = pc->proc.io->readString(Elf::Addr(code.co_name) + offsetof(PyBytesObject, ob_sval));
            auto file = pc->proc.io->readString(Elf::Addr(code.co_filename) + offsetof(PyBytesObject, ob_sval));
            pc->os << pc->prefix() << func << " in " << file << ":" << lineNo << "\n";

            if (pc->options[PstackOption::doargs]) {

                Elf::Addr flocals = remoteAddr + offsetof(PyFrameObject, f_localsplus);

                pc->depth++;

                printTupleVars<PyV>(pc, Elf::Addr(code.co_varnames), flocals, "fastlocals", code.co_nlocals);
                flocals += code.co_nlocals * sizeof (PyObject *);

                auto cellcount = printTupleVars(pc, Elf::Addr(code.co_cellvars), flocals, "cells");
                flocals += cellcount * sizeof (PyObject *);

                printTupleVars(pc, Elf::Addr(code.co_freevars), flocals, "freevars");

                --pc->depth;
            }
        }

        if (pc->options[PstackOption::doargs] && pfo->f_locals != 0) {
            pc->depth++;
            pc->os << pc->prefix() << "locals: " << std::endl;
            pc->print(Elf::Addr(pfo->f_locals));
            pc->depth--;
        }

        return Elf::Addr(pfo->f_back);
    }
    const char *type() const override { return "PyFrame_Type"; }
    bool dupdetect() const override { return true; }
};

template <int PyV>
const char *
PythonPrinter<PyV>::prefix() const
{
    static const char spaces[] =
        "                                           "
        "                                           "
        "                                           "
        "                                           "
        "                                           "
        "                                           ";

    return spaces + sizeof spaces - 1 - depth * 4;
}

template<int PyV>
PythonTypePrinter<PyV>::PythonTypePrinter()
{
    all.insert(this);
}

template<int PyV>
PythonTypePrinter<PyV>::~PythonTypePrinter()
{
    all.erase(this);
}


template<int PyV>
void
PythonPrinter<PyV>::printStacks()
{
    Elf::Addr ptr;
    for (proc.io->readObj(interp_head, &ptr); ptr; )
        ptr = printInterp(ptr);
}


template <int PyV> bool PythonPrinter<PyV>::interpFound() const {
    return interp_head != 0;
}

template <int PyV> void PythonPrinter<PyV>::findInterpreter() {

    // First search the ELF symbol table.
    try {
        auto interp_headp = proc.findSymbol("Py_interp_headp", false,
                [this](Elf::Addr loadAddr, const Elf::Object::sptr &o) {
                libpython = o;
                libpythonAddr = loadAddr;
                auto name = stringify(*o->io);
                return name.find("python") != std::string::npos;
                });
        if (verbose)
            *debug << "found interp_headp in ELF syms" << std::endl;
        proc.io->readObj(interp_headp, &interp_head);
        return;
    }
    catch (...) {
    }
    findInterpHeadFallback();
}

template <int PyV>
PythonPrinter<PyV>::PythonPrinter(Process &proc_, std::ostream &os_, const PstackOptions &options_)
    : proc(proc_)
    , os(os_)
    , depth(0)
    , interp_head(0)
    , libpython(nullptr)
    , options(options_)
{
    findInterpreter();
    if (!interpFound())
        return;

    static HeapPrinter<PyV> heapPrinter;
    static StringPrinter<PyV> stringPrinter;
    static FloatPrinter<PyV> floatPrinter;
    static ModulePrinter<PyV> modulePrinter;
    static ListPrinter<PyV> listPrinter;
    static TypePrinter<PyV> typePrinter;
    static LongPrinter<PyV> longPrinter;
    static FramePrinter<PyV> framePrinter;

    for (auto ps : PythonTypePrinter<PyV>::all) {
        if (ps->type() == nullptr)
            continue; // heapPrinter is used specially.
        auto sym = libpython->findDynamicSymbol(ps->type());
        if (!sym)
            throw Exception() << "failed to find python symbol " << ps->type();
        printers[(const _typeobject *)(libpythonAddr + sym.symbol.st_value)] = ps;
    }
}

template <int PyV>
void
PythonPrinter<PyV>::print(Elf::Addr remoteAddr) const {
    if (depth > 10000) {
        os << "too deep" << std::endl;
        return;
    }
    depth++;
    try {
        while (remoteAddr) {
            auto baseObj = readPyObj<PyV, PyVarObject>(*proc.io, remoteAddr);
            if (((PyObject *)&baseObj)->ob_refcnt == 0) {
                os << "(dead object)";
            }

            const PythonTypePrinter<PyV> *printer = printers.at(reinterpret_cast<const PyObject *>(&baseObj)->ob_type);

            auto &pto = types[reinterpret_cast<PyObject *>(&baseObj)->ob_type];
            if (pto == nullptr) {
                pto.reset((_typeobject *)malloc(sizeof(PyTypeObject)));
                readPyObj<PyV, PyTypeObject>(*proc.io,
                        (Elf::Addr)reinterpret_cast<PyObject *>(&baseObj)->ob_type,
                        pto.get());
            }

            if (printer == 0) {
                std::string tn;
                tn = proc.io->readString(Elf::Addr(pto->tp_name));
                if (tn == "NoneType") {
                    os << "None";
                    break;
                } else if (printer == 0 && (pto->tp_flags & Py_TPFLAGS_HEAPTYPE)) {
                    static HeapPrinter<PyV> heapPrinter;
                    printer = &heapPrinter;
                } else {
                    os <<  remoteAddr << " unprintable-type-" << tn << "@"<< ((PyObject *)&baseObj)->ob_type << std::endl;
                    break;
                }
            }

            if (printer->dupdetect() && visited.find(remoteAddr ) != visited.end()) {
                os << "(already seen)";
                break;
            }

            if (printer->dupdetect())
                visited.insert(remoteAddr);

            size_t size = pto->tp_basicsize;
            size_t itemsize = pto->tp_itemsize;
            ssize_t fullSize;
            if (itemsize != 0) {
                // object is a variable length object:
                if (baseObj.ob_size > 65536 || baseObj.ob_size < 0) {
                    os << "(skip massive object " << baseObj.ob_size << ")";
                    break;
                }
                fullSize = size + itemsize * baseObj.ob_size;
            } else {
                fullSize = size;
            }
            char buf[fullSize];
            proc.io->readObj(remoteAddr, buf, fullSize);
            remoteAddr = printer->print(this, (const PyObject *)buf, pto.get(), remoteAddr);
        }
    }
    catch (...) {
        os <<  "(print failed)";
    }
    --depth;
}

/*
 * process one python thread in an interpreter, at remote addr "ptr". 
 * returns the address of the next thread on the list.
 */
template <int PyV>
Elf::Addr
PythonPrinter<PyV>::printThread(Elf::Addr ptr)
{
    auto thread = readPyObj<PyV, PyThreadState>(*proc.io, ptr);
    size_t toff;
    if (thread.thread_id && pthreadTidOffset(proc, &toff)) {
        Elf::Addr tidptr = thread.thread_id + toff;
        pid_t tid;
        proc.io->readObj(tidptr, &tid);
        os << "pthread: 0x" << std::hex << thread.thread_id << std::dec << ", lwp " << tid;
    } else {
        os << "anonymous thread";
    }
    os << "\n";
    print(Elf::Addr(thread.frame));
    return Elf::Addr(thread.next);
}

/*
 * Process one python interpreter in the process at remote address ptr
 * Returns the address of the next interpreter on on the process's list.
 */
template <int PyV>
Elf::Addr
PythonPrinter<PyV>::printInterp(Elf::Addr ptr)
{
    // these are the first two fields in PyInterpreterState - next and tstate_head.
    struct State {
        Elf::Addr next;
        Elf::Addr head;
    };
    State state;
    proc.io->readObj(ptr, &state);
    os << "---- interpreter @" << std::hex << ptr << std::dec << " -----" << std::endl ;
    for (Elf::Addr tsp = state.head; tsp; ) {
        tsp = printThread(tsp);
        os << std::endl;
    }
    return state.next;
}
