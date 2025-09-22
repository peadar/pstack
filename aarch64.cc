// Copyright (c) 2025 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include <cstdint>
#include <type_traits>
#include "libpstack/elf.h"
namespace pstack::Procman {


const ArchRegs registers {
   { "general",
      {
         { 0, "regs[0]" },
         { 1, "regs[1]" },
         { 2, "regs[2]" },
         { 3, "regs[3]" },
         { 4, "regs[4]" },
         { 5, "regs[5]" },
         { 6, "regs[6]" },
         { 7, "regs[7]" },
         { 8, "regs[8]" },
         { 9, "regs[9]" },
         { 10, "regs[10]" },
         { 11, "regs[11]" },
         { 12, "regs[12]" },
         { 13, "regs[13]" },
         { 14, "regs[14]" },
         { 15, "regs[15]" },
         { 16, "regs[16]" },
         { 17, "regs[17]" },
         { 18, "regs[18]" },
         { 19, "regs[19]" },
         { 20, "regs[20]" },
         { 21, "regs[21]" },
         { 22, "regs[22]" },
         { 23, "regs[23]" },
         { 24, "regs[24]" },
         { 25, "regs[25]" },
         { 26, "regs[26]" },
         { 27, "regs[27]" },
         { 28, "regs[28]" },
         { 29, "regs[29]" },
         { 30, "regs[30]" },
         { 31, "sp" },
         { 32, "pc" },
      },
   },
   { "fpsimd", 
      {
         { 64, "v[0]" },
         { 65, "v[1]" },
         { 66, "v[2]" },
         { 67, "v[3]" },
         { 68, "v[4]" },
         { 69, "v[5]" },
         { 70, "v[6]" },
         { 71, "v[7]" },
         { 72, "v[8]" },
         { 73, "v[9]" },
         { 74, "v[10]" },
         { 75, "v[11]" },
         { 76, "v[12]" },
         { 77, "v[13]" },
         { 78, "v[14]" },
         { 79, "v[15]" },
         { 80, "v[16]" },
         { 81, "v[17]" },
         { 82, "v[18]" },
         { 83, "v[19]" },
         { 84, "v[20]" },
         { 85, "v[21]" },
         { 86, "v[22]" },
         { 87, "v[23]" },
         { 88, "v[24]" },
         { 89, "v[25]" },
         { 90, "v[26]" },
         { 91, "v[27]" },
         { 92, "v[28]" },
         { 93, "v[29]" },
         { 94, "v[30]" },
         { 95, "v[31]" },

         // Thse are not documented as having DWARF ids that I can see.
         { -2, "fpsr" },
         { -1, "fpcr" },
      }
   },
};

template <typename Regs, typename Op>
auto opReg(Regs &regs, int reg, Op op) {
   uintmax_t notused{};
   switch (reg) {
      case -2:
         return op(regs.fpsimd.fpsr);

      case -1:
         return op(regs.fpsimd.fpcr);

      case 0 ... 30:
         // Treat these as an Elf::Addr - they are 'unsigned long long', which
         // for this platform is the same as "unsigned long", which is
         // "Elf::Addr", but it is a distinct type. For the sake of the
         // std::variant we hold the register values in, make them match up.
         return op(reinterpret_cast<typename Op::cv_t<Elf::Addr>&>(regs.user.regs[reg]));

      case 31:
         return op(reinterpret_cast<typename Op::cv_t<Elf::Addr>&>(regs.user.sp));

      case 32:
         return op(reinterpret_cast<typename Op::cv_t<Elf::Addr>&>(regs.user.pc));

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
         return op(reinterpret_cast<typename Op::cv_t<Simd128>&>(regs.fpsimd.vregs[reg - 64]));

      case 96 ... 127: // VG x 64-bit vector regs.
      default:
         return op(notused);

   }
};


}

