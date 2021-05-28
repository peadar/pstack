#include <stddef.h>
#define Py_BUILD_CORE
#include <Python.h>
#if PY_VERSION_HEX >= 0x03090000
#include <internal/pycore_pystate.h>
#elif PY_VERSION_HEX >= 0x3070000
#include <internal/pystate.h>
#else
#error "no support for this version of python"
#endif

size_t pyInterpOffset() {
   return offsetof(_PyRuntimeState, interpreters) + offsetof(struct pyinterpreters, head);
}
