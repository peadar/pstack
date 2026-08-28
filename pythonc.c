#ifdef WITH_PYTHON3
#include <stddef.h>
#define Py_BUILD_CORE
#include <Python.h>
#if PY_VERSION_HEX >= 0x3090000 && PY_VERSION_HEX < 0x30a0000
#include <internal/pycore_pystate.h>
size_t pyInterpOffset() {
   return offsetof(_PyRuntimeState, interpreters) + offsetof(struct pyinterpreters, head);
}
#else
size_t pyInterpOffset() {
   return (size_t)-1;
}
#endif
#endif
