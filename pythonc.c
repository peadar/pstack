#include <stddef.h>
#include "Python.h"
#define Py_BUILD_CORE
#include "internal/pycore_pystate.h"

size_t pyInterpOffset() {
   return offsetof(_PyRuntimeState, interpreters) + offsetof(struct pyinterpreters, head);
}
