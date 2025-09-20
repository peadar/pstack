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
      case 0: return op( regs.user.rax );
      case 1: return op( regs.user.rdx );
      case 2: return op( regs.user.rcx );
      case 3: return op( regs.user.rbx );
      case 4: return op( regs.user.rsi );
      case 5: return op( regs.user.rdi );
      case 6: return op( regs.user.rbp );
      case 7: return op( regs.user.rsp );
      case 8: return op( regs.user.r8 );
      case 9: return op( regs.user.r9 );
      case 10: return op( regs.user.r10 );
      case 11: return op( regs.user.r11 );
      case 12: return op( regs.user.r12 );
      case 13: return op( regs.user.r13 );
      case 14: return op( regs.user.r14 );
      case 15: return op( regs.user.r15 );
      case 16: return op( regs.user.rip );

      case 17 ... 32: {
         // XMM registers 0-15
         auto ptr = const_cast<__uint128_t *>(reinterpret_cast<const __uint128_t *>(regs.fp.xmm_space));
         return op( ptr[reg - 17] );
      }

      case 33 ... 40: {
         // i387 floating point regs st0-st7
         auto ptr = const_cast<__uint128_t *>(reinterpret_cast<const __uint128_t *>(regs.fp.st_space));
         return op( ptr[reg - 33] );
      }

      case 41 ... 48: {
         // i386 MMX regs (aliasing old i387 FP regs)
         auto ptr = const_cast<__uint128_t *>(reinterpret_cast<const __uint128_t *>(regs.fp.st_space));
         return op(ptr[reg - 41]);
      }

      case 49: return op(regs.user.eflags);
      case 50: return op(regs.user.es);
      case 51: return op(regs.user.cs);
      case 52: return op(regs.user.ss);
      case 53: return op(regs.user.ds);
      case 54: return op(regs.user.fs);
      case 55: return op(regs.user.gs);

      case 56 ... 57: // reserved.
               return op(notused);

      case 58: return op(regs.user.fs_base);
      case 59: return op(regs.user.gs_base);

      case 60 ... 61: // reserved
               return op(notused);
      case 64: return op(regs.fp.mxcsr);
      case 65: return op(regs.fp.cwd);
      case 66: return op(regs.fp.swd);
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

