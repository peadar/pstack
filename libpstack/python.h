#include <python2.7/Python.h>
#include <python2.7/frameobject.h>
#include <python2.7/longintrepr.h>

struct PythonPrinter;
typedef Elf_Addr (*python_printfunc)(const PyObject *pyo, const PyTypeObject *, PythonPrinter *pc, Elf_Addr);
struct PyPrinterEntry {
    python_printfunc printer;
    bool dupdetect;
    PyPrinterEntry(python_printfunc, bool dupdetect);
};

struct PythonPrinter {
    void addPrinter(const char *symbol, python_printfunc func, bool dupDetect);
    void print(Elf_Addr remoteAddr);
    std::map<Elf_Addr, PyTypeObject> types;

    PythonPrinter(Process &proc_, std::ostream &os_);
    const char *prefix() const;
    void printStacks();
    Elf_Addr printThread(Elf_Addr);
    Elf_Addr printInterp(Elf_Addr);

    Process &proc;
    std::ostream &os;
    std::set<Elf_Addr> visited;
    mutable int depth;
    Elf_Addr interp_head;
    Process::LoadedObject *libPython;
    std::map<Elf_Addr, PyPrinterEntry> printers;
    PyPrinterEntry *heapPrinter;
};
