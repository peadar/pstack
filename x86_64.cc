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
         { 65, "cwd" },
         { 66, "swd" },

         { 64, "mxcsr" },
         
         { 33, "st[0]" },
         { 34, "st[1]" },
         { 35, "st[2]" },
         { 36, "st[3]" },
         { 37, "st[4]" },
         { 38, "st[5]" },
         { 39, "st[6]" },
         { 40, "st[7]" },

         // Does not appear in the ABI spec.
         { -1, "ftw" },
         { -2, "fop" },
         { -3, "rip" },
         { -4, "rdp" },
         { -5, "mxcr_mask" },
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

inline Elf::Addr &asaddr(unsigned long long &rhs) {
   return *reinterpret_cast<Elf::Addr *>(&rhs);
}

inline const Elf::Addr &asaddr(const unsigned long long &rhs) {
   return *reinterpret_cast<const Elf::Addr *>(&rhs);
}


template <typename Regs, typename Op>
void opReg(Regs &regs, int reg, Op op) {
   uintmax_t notused{};


   // Note the values below for the registers are cast to Elf::Addr. Elf::Addr
   // is `unsigned long`, while the user_regs_struct uses the distinct type
   // `unsigned long long`, which is also a 64-bit unsigned integer. Casting to
   // the common Elf type loses no information and allows our variants to
   // behave sanely
   switch (reg) {
      case 0: return op(asaddr(regs.user.rax));
      case 1: return op(asaddr(regs.user.rdx));
      case 2: return op(asaddr(regs.user.rcx));
      case 3: return op(asaddr(regs.user.rbx));
      case 4: return op(asaddr(regs.user.rsi));
      case 5: return op(asaddr(regs.user.rdi));
      case 6: return op(asaddr(regs.user.rbp));
      case 7: return op(asaddr(regs.user.rsp));
      case 8: return op(asaddr(regs.user.r8));
      case 9: return op(asaddr(regs.user.r9));
      case 10: return op(asaddr(regs.user.r10));
      case 11: return op(asaddr(regs.user.r11));
      case 12: return op(asaddr(regs.user.r12));
      case 13: return op(asaddr(regs.user.r13));
      case 14: return op(asaddr(regs.user.r14));
      case 15: return op(asaddr(regs.user.r15));
      case 16: return op(asaddr(regs.user.rip));

      case 17 ... 32: {
         auto ptr = reinterpret_cast<typename Op::cv_t<Simd128> *>(regs.fp.xmm_space);
         return op( ptr[reg - 17] );
      }

      case 33 ... 40: {
         // i387 floating point regs st0-st7. The "long double" on x86_64 is
         // stored using the 128-bit extension of the 80-bit value in st0-7,
         // just like st_space.
         auto ptr = reinterpret_cast<typename Op::cv_t<long double> *>(regs.fp.st_space);
         return op( ptr[reg - 33] );
      }

      case 41 ... 48: {
         // MMX registers. These alias the st0-st7 regs above, but only provide
         // 64-bit SIMD state.
         auto ptr = reinterpret_cast<typename Op::cv_t<SimdInt64> *>(regs.fp.st_space);
         return op(ptr[(reg - 41) * 2]);
      }

      case 49: return op(asaddr(regs.user.eflags));
      case 50: return op(asaddr(regs.user.es));
      case 51: return op(asaddr(regs.user.cs));
      case 52: return op(asaddr(regs.user.ss));
      case 53: return op(asaddr(regs.user.ds));
      case 54: return op(asaddr(regs.user.fs));
      case 55: return op(asaddr(regs.user.gs));

      case 56 ... 57: // reserved.
               return op(notused);

      case 58: return op(asaddr(regs.user.fs_base));
      case 59: return op(asaddr(regs.user.gs_base));

      // most of what's below are not available in the registers we hold on to
      // Support would require putting the XSAVE state in CoreRegisters, and 
      // grovelling through that instead.
      // We only try supporting x86-64-v2 for now, so the SSE registers above
      // are as much as we care about. Linux may use AVX512 etc on systems
      // that support that via IFUNCs, but we won't return register state
      // for those for now.
      case 60 ... 61: // reserved
               return op(notused);

      // The CPU registers for the following three entries are smaller than the
      // type used in the user_regs_struct, but we represent them as what's in
      // there for consistency 
      case 64:
               return op(regs.fp.mxcsr);
      case 65:
               return op(regs.fp.cwd);
      case 66:
               return op(regs.fp.swd);
      case 67 ... 82: // xmm16-31
               return op(notused);
      case 83 ... 117: // reserved
               return op(notused);
      case 118 ... 125: // k0-k7
               return op(notused);
      case 126 ... 129: // reserved
               return op(notused);
      case 130 ... 145: // APX integer registers
               return op(notused);
      case 146 ... 153: // tile regs.
               return op(notused);
      case 154: // tilecfg.
               return op(notused);

      // Not provided in spec.
      case  -1:
               return op(regs.fp.ftw);
      case  -2:
               return op(regs.fp.fop);
      case  -3:
               return op(regs.fp.rip);
      case  -4:
               return op(regs.fp.rdp);
      case  -5:
               return op(regs.fp.mxcr_mask);

      default:
               throw std::logic_error("invalid register number");
   }
};


}

