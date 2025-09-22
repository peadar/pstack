// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
#include <type_traits>
#include "libpstack/elf.h"
#include "libpstack/arch.h"

namespace pstack::Procman {

template <typename Regs, typename Op>
auto opReg(Regs &regs, int reg, Op op) {
   uintmax_t notused{};
   switch (reg) {
      using addr_t = typename Op::cv_t<Elf::Addr>;

      case 0: return op( reinterpret_cast<addr_t &>(regs.user.eax ) );
      case 1: return op( reinterpret_cast<addr_t &>(regs.user.ecx ) );
      case 2: return op( reinterpret_cast<addr_t &>(regs.user.edx ) );
      case 3: return op( reinterpret_cast<addr_t &>(regs.user.ebx ) );
      case 4: return op( reinterpret_cast<addr_t &>(regs.user.esp ) );
      case 5: return op( reinterpret_cast<addr_t &>(regs.user.ebp ) );
      case 6: return op( reinterpret_cast<addr_t &>(regs.user.esi ) );
      case 7: return op( reinterpret_cast<addr_t &>(regs.user.edi ) );
      case 8: return op( reinterpret_cast<addr_t &>(regs.user.eip ) );
      case 9: return op( reinterpret_cast<addr_t &>(regs.user.eflags ) );
      case 40: return op( reinterpret_cast<addr_t &>(regs.user.xes ) );
      case 41: return op( reinterpret_cast<addr_t &>(regs.user.xcs ) );
      case 42: return op( reinterpret_cast<addr_t &>(regs.user.xss ) );
      case 43: return op( reinterpret_cast<addr_t &>(regs.user.xds ) );
      case 44: return op( reinterpret_cast<addr_t &>(regs.user.xfs ) );
      case 45: return op( reinterpret_cast<addr_t &>(regs.user.xgs ) );

      default:
               return op(notused);
   }
};


}

