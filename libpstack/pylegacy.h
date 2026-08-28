#ifndef PSTACK_PYLEGACY
#define PSTACK_PYLEGACY
#include "libpstack/python.h"
#ifdef WITH_PYTHON3
#include <Python.h>
#if PY_VERSION_HEX >= 0x309000 && PY_VERSION_HEX < 0x30a000
#define HAVE_PYTHON39
#else
#warning "Legacy python support (WITH_PYTHON3) requested, but incompatible python3 interpreter found"
#endif
#endif
#endif
