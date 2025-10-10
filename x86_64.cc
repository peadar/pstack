// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
#include <type_traits>
#include "libpstack/elf.h"
namespace pstack::Procman {

template <typename Regs>
struct Simd64Space {
   int regno;
   Regs &regs;
   template <typename T> auto operator = (const T &) { return *this; }
   template <typename T> requires std::is_integral_v<T> operator T () const { return 0; }
};

template <typename Regs>
struct Simd128Space {
   int regno;
   Regs &regs;
   template <typename T> auto operator = (const T &) { return *this; }
   template <typename T> requires std::is_integral_v<T> operator T () const { return 0; }
};

struct RegGet {
   template <typename T> void operator()(const T &from, RegisterValue &to) const {
      to = from;
   }
   operator long () {
      return 0;
   }
   void operator()(const Simd128Space<const CoreRegisters> &from, RegisterValue &to) const;
   void operator()(const Simd64Space<const CoreRegisters> &from, RegisterValue &to) const;
};

struct RegSet {
   template <typename T> void operator()(T &to, const RegisterValue &from) const {
      std::visit([&to](auto branch) { to = branch; } , from);
   }
   void operator()(Simd128Space<CoreRegisters> &&to, const RegisterValue &from) const;
   void operator()(Simd64Space<CoreRegisters> &&to, const RegisterValue &from) const;
};

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
template <typename Regs, typename Op, typename Value>
void opReg(Regs &regs, Op op, int reg, Value &value) {
   char notused{};
   // Note the values below for the registers are cast to Elf::Addr. Elf::Addr
   // is `unsigned long`, while the user_regs_struct uses the distinct type
   // `unsigned long long`, which is also a 64-bit unsigned integer. Casting to
   // the common Elf type loses no information and allows our variants to
   // behave sanely
   //
   switch (reg) {
      case 0:
         return op(regs.user.rax, value);
      case 1:
         return op(regs.user.rdx, value);
      case 2:
         return op(regs.user.rcx, value);
      case 3:
         return op(regs.user.rbx, value);
      case 4:
         return op(regs.user.rsi, value);
      case 5:
         return op(regs.user.rdi, value);
      case 6:
         return op(regs.user.rbp, value);
      case 7:
         return op(regs.user.rsp, value);
      case 8:
         return op(regs.user.r8, value);
      case 9:
         return op(regs.user.r9, value);
      case 10:
         return op(regs.user.r10, value);
      case 11:
         return op(regs.user.r11, value);
      case 12:
         return op(regs.user.r12, value);
      case 13:
         return op(regs.user.r13, value);
      case 14:
         return op(regs.user.r14, value);
      case 15:
         return op(regs.user.r15, value);
      case 16:
         return op(regs.user.rip, value);
      case 17 ... 32:
         return op(Simd128Space(reg, regs), value);
      case 33 ... 40:
         // i387 floating point regs st0-st7. The "long double" on x86_64 is
         // stored using the 128-bit extension of the 80-bit value in st0-7,
         // just like st_space.
         return op( Simd64Space(reg - 33, regs), value );
#if 0
      case 41 ... 48:
         // MMX registers. These alias the st0-st7 regs above, but only provide
         // 64-bit SIMD state.
         return op( Simd64Space((reg - 41) * 2), value);
#endif
      case 49:
         return op(regs.user.eflags, value);
      case 50:
         return op(regs.user.es, value);
      case 51:
         return op(regs.user.cs, value);
      case 52:
         return op(regs.user.ss, value);
      case 53:
         return op(regs.user.ds, value);
      case 54:
         return op(regs.user.fs, value);
      case 55:
         return op(regs.user.gs, value);
      case 58:
         return op(regs.user.fs_base, value);
      case 59:
         return op(regs.user.gs_base, value);

      // most of what's below are not available in the registers we hold on to
      // Support would require putting the XSAVE state in CoreRegisters, and 
      // grovelling through that instead.
      // We only try supporting x86-64-v2 for now, so the SSE registers above
      // are as much as we care about. Linux may use AVX512 etc on systems
      // that support that via IFUNCs, but we won't return register state
      // for those for now.
      case 60 ... 61: // reserved
         return op(notused, value);

      // The CPU registers for the following three entries are smaller than the
      // type used in the user_regs_struct, but we represent them as what's in
      // there for consistency 
      case 64:
         return op(regs.fp.mxcsr, value);
      case 65:
         return op(regs.fp.cwd, value);
      case 66:
         return op(regs.fp.swd, value);
      case 67 ... 82: // xmm16-31
         return op(notused, value);
      case 83 ... 117: // reserved
         return op(notused, value);
      case 118 ... 125: // k0-k7
         return op(notused, value);
      case 126 ... 129: // reserved
         return op(notused, value);
      case 130 ... 145: // APX integer registers
         return op(notused, value);
      case 146 ... 153: // tile regs.
         return op(notused, value);
      case 154: // tilecfg.
         return op(notused, value);

      // Not provided in spec.
      case  -1:
         return op(regs.fp.ftw, value);
      case  -2:
         return op(regs.fp.fop, value);
      case  -3:
         return op(regs.fp.rip, value);
      case  -4:
         return op(regs.fp.rdp, value);
      case  -5:
         return op(regs.fp.mxcr_mask, value);
      case 56 ... 57:
         throw std::logic_error(stringify("unsupported register ", reg));
      default:
         throw std::logic_error(stringify("invalid register ", reg));
   }
};


}

