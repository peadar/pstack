// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
#include "libpstack/arch.h"

namespace pstack::Procman {
struct Setter {
   const RegisterValue &from;
   template <typename T> using cv_t = T;
   template <typename T> void operator()(T &to) const {
         to = std::get<T>(from);
   };
};

struct Getter {
   RegisterValue &to;
   template <typename T> using cv_t = const T;
   template <typename T> void operator()(const T &from) const {
         to = from;
   };
};
}

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
void CoreRegisters::setDwarf(int regId, RegisterValue value) {
   opReg(*this, regId, Setter(value) );
};

RegisterValue CoreRegisters::getDwarf(int regId) const {
   RegisterValue rv;
   opReg(*this, regId, Getter{rv});
   return rv;
};
}
