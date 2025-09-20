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

      case 0: return op( regs.user.eax );
      case 1: return op( regs.user.ecx );
      case 2: return op( regs.user.edx );
      case 3: return op( regs.user.ebx );
      case 4: return op( regs.user.esp );
      case 5: return op( regs.user.ebp );
      case 6: return op( regs.user.esi );
      case 7: return op( regs.user.edi );
      case 8: return op( regs.user.eip );
      case 9: return op( regs.user.eflags );
      case 40: return op( regs.user.xes );
      case 41: return op( regs.user.xcs );
      case 42: return op( regs.user.xss );
      case 43: return op( regs.user.xds );
      case 44: return op( regs.user.xfs );
      case 45: return op( regs.user.xgs );

      default:
               return op(notused);
   }
};

void setReg(Elf::CoreRegisters &regs, int reg, uintmax_t value) {
   opReg(regs, reg, RegSet(value));
};

uintmax_t getReg(const Elf::CoreRegisters &regs, int reg) {
   return opReg(regs, reg, [](const uintmax_t &loc) -> uintmax_t { return loc; });
};



}

