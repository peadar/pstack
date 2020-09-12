#include <python3.8/Python.h>
#include <python3.8/frameobject.h>
#include <python3.8/longintrepr.h>
#include <python3.8/longintrepr.h>
#include "libpstack/python.h"

template<> std::set<const PythonTypePrinter<3> *> PythonTypePrinter<3>::all = std::set<const PythonTypePrinter<3> *>();
template <>
char PythonTypePrinter<3>::pyBytesType[] = "PyBytes_Type";

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

template<>
void PythonPrinter<3>::findInterpHeadFallback() {
    libpython = nullptr;

    Elf::Addr pyRuntime;
    std::tie(libpython, libpythonAddr, pyRuntime) = proc.findSymbolDetail("_PyRuntime", false);
    if (pyRuntime == 0)
       return;
#if 0
    typedef struct pyruntimestate {
        /* Is Python pre-initialized? Set to 1 by Py_PreInitialize() */
        int pre_initialized;

        /* Is Python core initialized? Set to 1 by _Py_InitializeCore() */
        int core_initialized;

        /* Is Python fully initialized? Set to 1 by Py_Initialize() */
        int initialized;

        PyThreadState *finalizing;

        struct pyinterpreters {
"void *"->  PyThread_type_lock mutex;
WANT THIS-> PyInterpreterState *head;
            PyInterpreterState *main;
            /* _next_interp_id is an auto-numbered sequence of small
               integers.  It gets initialized in _PyInterpreterState_Init(),
               which is called in Py_Initialize(), and used in
               PyInterpreterState_New().  A negative interpreter ID
               indicates an error occurred.  The main interpreter will
               always have an ID of 0.  Overflow results in a RuntimeError.
               If that becomes a problem later then we can adjust, e.g. by
               using a Python int. */
            int64_t next_id;
        } interpreters;
        // XXX Remove this field once we have a tp_* slot.
        struct _xidregistry {
            PyThread_type_lock mutex;
            struct _xidregitem *head;
        } xidregistry;

        unsigned long main_thread;

#define NEXITFUNCS 32
        void (*exitfuncs[NEXITFUNCS])(void);
        int nexitfuncs;

        struct _gc_runtime_state gc;
        struct _ceval_runtime_state ceval;
        struct _gilstate_runtime_state gilstate;

        PyPreConfig preconfig;

        Py_OpenCodeHookFunction open_code_hook;
        void *open_code_userdata;
        _Py_AuditHookEntry *audit_hook_head;

    } _PyRuntimeState;
#endif
    interp_head = pyRuntime + sizeof(int) * 4  + sizeof(void *)*2;
    if (verbose)
       *debug << "python library is " << *libpython->io
          << ", _PyRuntime at " << pyRuntime
          << ", interp head is " << interp_head << std::endl;
}

#include "python.tcc"

template struct PythonPrinter<3>;
