// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
#include <type_traits>
#include "libpstack/elf.h"
#include "libpstack/arch.h"

namespace pstack::Procman {
const ArchRegs registers {
   {
      // see psABI-i386.pdf
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
            { 41, "xcs" },
            { 42, "xss" },
            { 43, "xds" },
            { 40, "xes" },
            { 44, "xfs" },
            { 45, "xgs" },
         }
   },

   { "i387" ,
      {
         { -1, "cwd" },
         { -2, "swd" },
         { -3, "twd" },
         { -4, "fip" },
         { -5, "fcs" },
         { -6, "foo" },
         { -7, "fos" },
         { 39, "mxcsr" },
         { 11, "st[0]" },
         { 12, "st[1]" },
         { 13, "st[2]" },
         { 14, "st[3]" },
         { 15, "st[4]" },
         { 16, "st[5]" },
         { 17, "st[6]" },
         { 18, "st[7]" },
         { 21, "xmm[0]" },
         { 22, "xmm[1]" },
         { 23, "xmm[2]" },
         { 24, "xmm[3]" },
         { 25, "xmm[4]" },
         { 26, "xmm[5]" },
         { 27, "xmm[6]" },
         { 28, "xmm[7]" },
      }
   },

};

template <typename Regs, typename Op, typename Value>
void opReg(Regs &regs, Op op, int reg, Value &value) {
   switch (reg) {
      case -1:
         regop(op, regs.fpx.cwd, value);
         break;
      case -2:
         regop(op, regs.fpx.swd, value);
         break;
      case -3:
         regop(op, regs.fpx.twd, value);
         break;
      case -4:
         regop(op, regs.fpx.fip, value);
         break;
      case -5:
         regop(op, regs.fpx.fcs, value);
         break;
      case -6:
         regop(op, regs.fpx.foo, value);
         break;
      case -7:
         regop(op, regs.fpx.fos, value);
         break;

      case 0:
         regop(op, regs.user.eax, value);
         break;
      case 1:
         regop(op, regs.user.ecx, value);
         break;
      case 2:
         regop(op, regs.user.edx, value);
         break;
      case 3:
         regop(op, regs.user.ebx, value);
         break;
      case 4:
         regop(op, regs.user.esp, value);
         break;
      case 5:
         regop(op, regs.user.ebp, value);
         break;
      case 6:
         regop(op, regs.user.esi, value);
         break;
      case 7:
         regop(op, regs.user.edi, value);
         break;
      case 8:
         regop(op, regs.user.eip, value);
         break;
      case 9:
         regop(op, regs.user.eflags, value);
         break;

      case 11 ... 18: {
         auto &st = *reinterpret_cast< typename Op::Reg<i387Float> *> (regs.fpx.st_space + (reg-11) * 4);
         regop(op, st, value);
         break;
      }

      case 21 ... 28: {
         auto &st = *reinterpret_cast< typename Op::Reg<Simd128> *> (regs.fpx.xmm_space + (reg-21) * 4);
         regop(op, st, value);
         break;
      }

      case 39:
         regop(op, regs.fpx.mxcsr, value);
         break;

      case 40:
         regop(op, regs.user.xes, value);
         break;
      case 41:
         regop(op, regs.user.xcs, value);
         break;
      case 42:
         regop(op, regs.user.xss, value);
         break;
      case 43:
         regop(op, regs.user.xds, value);
         break;
      case 44:
         regop(op, regs.user.xfs, value);
         break;
      case 45:
         regop(op, regs.user.xgs, value);
         break;
      default:
         throw std::logic_error("unhandled register");
   }
};
}
