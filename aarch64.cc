// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
#include <type_traits>
#include "libpstack/elf.h"
namespace pstack::Procman {

template <typename Regs, typename Op>
auto opReg(Regs &regs, int reg, Op op) {
   uintmax_t notused{};
   switch (reg) {
      case 0 ... 30:
         return op(regs.user.regs[reg]);
      case 31:
         return op(regs.user.sp);
      case 32:
         return op(regs.user.pc);
      case 33: // ELR_mode
      case 34: //RA_SIGN_STATE
      case 35: // TPIDRRO_ELO - readonly software thread id
      case 36 ... 39: // TPIDR_EL{0,3} - read/write software thread id
      case 40 ... 45: // reserved
      case 46: // VG
      case 47: // FFR
      case 48 ... 63: // VG x 8-bit SVE predicate registers.
         return op(notused);
      case 64 ...  95:
         return op(regs.fpsimd.vregs[reg - 64]);

      case 96 ... 127: // VG x 64-bit vector regs.
      default:
         return op(notused);

   }
};

void setReg(Elf::CoreRegisters &regs, int reg, std::uintmax_t value) {
   opReg(regs, reg, RegSet(value));
};

uintmax_t getReg(const Elf::CoreRegisters &regs, int reg) {
   return opReg(regs, reg, [](const uintmax_t &loc) -> uintmax_t { return loc; });
};



}

