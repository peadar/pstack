#include <python2.7/Python.h>
#include <python2.7/frameobject.h>
#include <python2.7/longintrepr.h>

struct PythonPrinter;
typedef Elf::Addr (*python_printfunc)(const PyObject *pyo, const PyTypeObject *, PythonPrinter *pc, Elf::Addr);
struct PyPrinterEntry {
    python_printfunc printer;
    bool dupdetect;
    PyPrinterEntry(python_printfunc, bool dupdetect);
};

struct PythonPrinter {
    void addPrinter(const char *symbol, python_printfunc func, bool dupDetect);
    void print(Elf::Addr remoteAddr);
    std::map<Elf::Addr, PyTypeObject> types;

    PythonPrinter(Process &proc_, std::ostream &os_, const PstackOptions &);
    const char *prefix() const;
    void printStacks();
    Elf::Addr printThread(Elf::Addr);
    Elf::Addr printInterp(Elf::Addr);

    Process &proc;
    std::ostream &os;
    std::set<Elf::Addr> visited;
    mutable int depth;
    Elf::Addr interp_head;
    const Process::LoadedObject *libPython;
    std::map<Elf::Addr, PyPrinterEntry> printers;
    PyPrinterEntry *heapPrinter;
    const PstackOptions &options;
};
