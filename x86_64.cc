// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
#include <type_traits>
#include "libpstack/elf.h"
namespace pstack::Procman {

// see https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
// Figure 3.36, page 57
const ArchRegs registers {

   { "general", 
      {
         { 0, "rax" },
         { 1, "rdx" },
         { 2, "rcx" },
         { 3, "rbx" },
         { 4, "rsi" },
         { 5, "rdi" },
         { 6, "rbp" },
         { 7, "rsp" },
         { 8, "r8"  },
         { 9, "r9"  },
         { 10, "r10"},
         { 11, "r11"},
         { 12, "r12"},
         { 13, "r13"},
         { 14, "r14"},
         { 15, "r15"},
         { 16, "rip"},
         { 49, "eflags" },
         { 50, "es" },
         { 51, "cs" },
         { 52, "ss" },
         { 53, "ds" },
         { 54, "fs" },
         { 55, "gs" },
         { 58, "fs_base" },
         { 59, "gs_base" },
      }
   },

   { "i387" ,
      {
         // Negative register numbers are for registers not specified by DWARF.
         { 65, "cwd" },
         { 66, "swd" },
         { -1, "ftw" },
         { -2, "fop" },
         { -3, "rip" },
         { -4, "rdp" },
         { 64, "mxcsr" },
         { -5, "mxcr_mask" },
         { 33, "st[0]" },
         { 34, "st[1]" },
         { 35, "st[2]" },
         { 36, "st[3]" },
         { 37, "st[4]" },
         { 38, "st[5]" },
         { 39, "st[6]" },
         { 40, "st[7]" },
      }
   },

   { "mmx",
      {
         { 41, "mm0" },
         { 42, "mm1" },
         { 43, "mm2" },
         { 44, "mm3" },
         { 45, "mm4" },
         { 46, "mm5" },
         { 47, "mm6" },
         { 48, "mm7" },
      }
   },

   { "sse",
      {
         { 17, "xmm[0]" },
         { 18, "xmm[1]" },
         { 19, "xmm[2]" },
         { 20, "xmm[3]" },
         { 21, "xmm[4]" },
         { 22, "xmm[5]" },
         { 23, "xmm[6]" },
         { 24, "xmm[7]" },
         { 25, "xmm[8]" },
         { 26, "xmm[9]" },
         { 27, "xmm[10]" },
         { 28, "xmm[11]" },
         { 29, "xmm[12]" },
         { 30, "xmm[13]" },
         { 31, "xmm[14]" },
         { 32, "xmm[15]" },
      }
   }
};

template <typename Regs, typename Op, typename Value>
void opReg(Regs &regs, Op op, int reg, Value &value) {
   char notused{};

   switch (reg) {
      case 0:
         regop(op, regs.user.rax, value);
         break;
      case 1:
         regop(op, regs.user.rdx, value);
         break;
      case 2:
         regop(op, regs.user.rcx, value);
         break;
      case 3:
         regop(op, regs.user.rbx, value);
         break;
      case 4:
         regop(op, regs.user.rsi, value);
         break;
      case 5:
         regop(op, regs.user.rdi, value);
         break;
      case 6:
         regop(op, regs.user.rbp, value);
         break;
      case 7:
         regop(op, regs.user.rsp, value);
         break;
      case 8:
         regop(op, regs.user.r8, value);
         break;
      case 9:
         regop(op, regs.user.r9, value);
         break;
      case 10:
         regop(op, regs.user.r10, value);
         break;
      case 11:
         regop(op, regs.user.r11, value);
         break;
      case 12:
         regop(op, regs.user.r12, value);
         break;
      case 13:
         regop(op, regs.user.r13, value);
         break;
      case 14:
         regop(op, regs.user.r14, value);
         break;
      case 15:
         regop(op, regs.user.r15, value);
         break;
      case 16:
         regop(op, regs.user.rip, value);
         break;
      case 17 ... 32: {
         auto &xmm = *reinterpret_cast< typename Op::Reg<Simd128> *> (regs.fp.xmm_space + (reg-17) * 4);
         regop(op, xmm, value);
         break;
      }
      case 33 ... 40: {
         auto &st = *reinterpret_cast< typename Op::Reg<i387Float> *> (regs.fp.st_space + (reg-33) * 4);
         regop(op, st, value);
         break;
      }
      case 41 ... 48: {
         // MMX registers. These alias the st0-st7 regs above, but only provide
         // 64-bit SIMD state.
         auto &st = *reinterpret_cast< typename Op::Reg<Simd64> *> (regs.fp.xmm_space + (reg-41) * 4);
         regop(op, st, value);
         break;
      }

      case 49:
         regop(op, regs.user.eflags, value);
         break;
      case 50:
         regop(op, regs.user.es, value);
         break;
      case 51:
         regop(op, regs.user.cs, value);
         break;
      case 52:
         regop(op, regs.user.ss, value);
         break;
      case 53:
         regop(op, regs.user.ds, value);
         break;
      case 54:
         regop(op, regs.user.fs, value);
         break;
      case 55:
         regop(op, regs.user.gs, value);
         break;
      case 58:
         regop(op, regs.user.fs_base, value);
         break;
      case 59:
         regop(op, regs.user.gs_base, value);
         break;

      // most of what's below are not available in the registers we hold on to
      // Support would require putting the XSAVE state in CoreRegisters, and 
      // grovelling through that instead.
      // We only try supporting x86-64-v2 for now, so the SSE registers above
      // are as much as we care about. Linux may use AVX512 etc on systems
      // that support that via IFUNCs, but we won't return register state
      // for those for now.
      case 60 ... 61: // reserved
         regop(op, notused, value);
         break;

      case 64:
         regop(op, regs.fp.mxcsr, value);
         break;
      case 65:
         regop(op, regs.fp.cwd, value);
         break;
      case 66:
         regop(op, regs.fp.swd, value);
         break;

      case 67 ... 82: // xmm16-31
         regop(op, notused, value);
         break;
      case 83 ... 117: // reserved
         regop(op, notused, value);
         break;
      case 118 ... 125: // k0-k7
         regop(op, notused, value);
         break;
      case 126 ... 129: // reserved
         regop(op, notused, value);
         break;
      case 130 ... 145: // APX integer registers
         regop(op, notused, value);
         break;
      case 146 ... 153: // tile regs.
         regop(op, notused, value);
         break;
      case 154: // tilecfg.
         regop(op, notused, value);
         break;

      // Not provided in spec.
      case  -1:
         regop(op, regs.fp.ftw, value);
         break;
      case  -2:
         regop(op, regs.fp.fop, value);
         break;
      case  -3:
         regop(op, regs.fp.rip, value);
         break;
      case  -4:
         regop(op, regs.fp.rdp, value);
         break;
      case  -5:
         regop(op, regs.fp.mxcr_mask, value);
         break;
      case 56 ... 57:
         throw std::logic_error(stringify("unsupported register ", reg));
      default:
         throw std::logic_error(stringify("invalid register ", reg));
   }
};

}

