#include "noreturn.h"
#include <stdlib.h>

int thisFunctionTerminatesTheProcess() {
    abort();
}

