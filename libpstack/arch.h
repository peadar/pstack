#ifndef pstack_arch_h
#define pstack_arch_h
#include <ucontext.h>
#include <sys/user.h>

#include <map>
#include <variant>
#include <unordered_map>
#include <string_view>
#include <cstdint>
#include <stdexcept>

#if defined( __i386__ )
#define IPREG 8
#define CFA_RESTORE_REGNO 4
// we need this because Elf::Addr is a different type to what's stored in the
// user_regs_struct . We'll conver this to an Elf::Addr as required, but we
// must extract values from the general purpose regsisters in CoreRegisters as
// this type
using gpreg = long;

#elif defined( __x86_64__ )
#define CFA_RESTORE_REGNO 7
#define IPREG 16

using gpreg = unsigned long long;


#elif defined( __ARM_ARCH )
#ifdef __aarch64__
using gpreg = uint64_t;
#define IPREG 32
#define CFA_RESTORE_REGNO 31
#else
// 32 bit ARM is not yet supported
#define IPREG 15
#define CFA_RESTORE_REGNO 13
#endif

#endif

namespace pstack::Procman {

// Many platforms will have a 128-bit SIMD register that can be treated as 2
// doubles or 4 floats, 4 integers, etc. Create a specific type for it. By
// "many platforms", I mean this fits x86_64 XMM registers well, and maybe the
// ARM fpsimd ones. Also, note that i386 has access to these, but not the
// 128-bit fields

union Simd128 {
   float f32[4];
   double f64[2];
   int8_t i8[16];
   uint8_t u8[16];
   int16_t i16[8];
   uint16_t u16[8];
   int32_t i32[4];
   uint32_t u32[4];
   int64_t i64[2];
   uint64_t u64[2];
#ifndef __i386__ // doesn't have 128-bit registers / doesn't support 128-bit ints.
   __int128_t i128;
   __uint128_t u128;
#endif
   operator long() const { throw std::logic_error("cannot convert SIMD value to scalar"); }
};

// This is for MMX.
union SimdInt64 {
   int8_t i8[16];
   uint8_t u8[16];
   int16_t i16[8];
   uint16_t u16[8];
   int32_t i32[4];
   uint32_t u32[4];
   int64_t i64[2];
   uint64_t u64[2];
   operator long() const { throw std::logic_error("cannot convert SIMD value to scalar"); }
};

using RegisterValue = std::variant<
   short,
   unsigned short,
   int,
   unsigned int,
   long int,
   unsigned long int,
   long long int,
   unsigned long long int,
   float,
   double,
   long double,
   SimdInt64,
#ifndef __i386__
   Simd128,
   __uint128_t,
   __int128_t,
#endif
   char
      >;

// These are the architecture specific types representing the NT_PRSTATUS registers.
struct CoreRegisters {
   user_regs_struct user;
#ifdef __aarch64__
   user_fpsimd_struct fpsimd;
#elif defined(__x86_64__)
   user_fpregs_struct fp;
#elif defined(__i386__)
   user_fpxregs_struct fpx;
#endif
   RegisterValue getDwarf(int reg) const;
   void setDwarf(int reg, const RegisterValue &val);
};

// Maps a name to its dwarf register index.
using DwarfNames = std::map<int, std::string_view>;

// Sets of registers for an architecture. Each architecture supports at least
// "general" registers.
using ArchRegs = std::unordered_map<std::string_view, DwarfNames>;
extern const ArchRegs registers;

#ifndef __aarch64__
void gregset2user(user_regs_struct &core, const gregset_t greg);
#endif
}
#endif
