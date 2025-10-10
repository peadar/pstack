// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
#include "libpstack/arch.h"

#ifdef __x86_64__
#include "x86_64.cc"
#endif
#ifdef __aarch64__
#include "aarch64.cc"
#endif
#ifdef __i386__
#include "i386.cc"
#endif

namespace pstack::Procman {
void CoreRegisters::setDwarf(int regId, const RegisterValue &value) {
   opReg(*this, RegSet{}, regId, value );
};

RegisterValue CoreRegisters::getDwarf(int regId) const {
   RegisterValue rv;
   opReg(*this, RegGet{}, regId, rv);
   return rv;
};
}
