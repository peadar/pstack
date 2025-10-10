// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
#include <type_traits>
#include "libpstack/elf.h"
#include "libpstack/arch.h"

namespace pstack::Procman {
const ArchRegs registers {
   {
      "general",
         {
            { 0, "eax" }, 
            { 1, "ecx" }, 
            { 2, "edx" }, 
            { 3, "ebx" }, 
            { 4, "esp" }, 
            { 5, "ebp" }, 
            { 6, "esi" }, 
            { 7, "edi" }, 
            { 8, "eip" }, 
            { 9, "eflags" }, 
            { 10, "xcs" }, 
            { 11, "xss" }, 
            { 12, "xds" }, 
            { 13, "xes" }, 
            { 14, "xfs" },
         }
   },

   { "i387" ,
         {
            { -10, "cwd" },
            { -9, "swd" },
            { -8, "twd" },

            { -6, "fip" },
            { -5, "fcs" },
            { -4, "foo" },
            { -3, "fos" },
            
            { 11, "st[0]" },
            { 12, "st[1]" },
            { 13, "st[2]" },
            { 14, "st[3]" },
            { 15, "st[4]" },
            { 16, "st[5]" },
            { 17, "st[6]" },
            { 18, "st[7]" },

            { 39, "mxcsr" },

            // Does not appear in the ABI spec.
            { -1, "ftw" },
            { -2, "fop" },
            { -3, "rip" },
            { -4, "rdp" },
            { -5, "mxcr_mask" },
         }
      },
};

template <typename Regs, typename Op, typename Value>
void opReg(Regs &regs, Op op, int reg, Value &value) {
   switch (reg) {
      case 0:
         return op(regs.user.eax, value);
      case 1:
         return op(regs.user.ecx, value);
      case 2:
         return op(regs.user.edx, value);
      case 3:
         return op(regs.user.ebx, value);
      case 4:
         return op(regs.user.esp, value);
      case 5:
         return op(regs.user.ebp, value);
      case 6:
         return op(regs.user.esi, value);
      case 7:
         return op(regs.user.edi, value);
      case 8:
         return op(regs.user.eip, value);
      case 9:
         return op(regs.user.eflags, value);
      case 40:
         return op(regs.user.xes, value);
      case 41:
         return op(regs.user.xcs, value);
      case 42:
         return op(regs.user.xss, value);
      case 43:
         return op(regs.user.xds, value);
      case 44:
         return op(regs.user.xfs, value);
      case 45:
         return op(regs.user.xgs, value);
      default:
         throw std::logic_error("unhandled register");
   }
};
}
