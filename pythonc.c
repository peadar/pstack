#include <stddef.h>
#define Py_BUILD_CORE
#include <Python.h>
#include <internal/pystate.h>

size_t pyInterpOffset() {
   return offsetof(_PyRuntimeState, interpreters) + offsetof(struct pyinterpreters, head);
}
