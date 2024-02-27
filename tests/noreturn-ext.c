#include "noreturn.h"
#include <stdlib.h>

__attribute__((noreturn, nothrow)) void thisFunctionTerminatesTheProcess() {
    abort();
}

