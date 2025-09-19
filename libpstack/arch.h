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
#include <vector>
#include <cstring>

namespace pstack::Procman {

#if defined( __i386__ )
#define IPREG 8
#define CFA_RESTORE_REGNO 4
using gpreg = long;

#elif defined( __x86_64__ )
#define CFA_RESTORE_REGNO 7
#define IPREG 16

using gpreg = unsigned long long;


#elif defined( __ARM_ARCH )
#ifdef __aarch64__
using gpreg = unsigned long long;
#define IPREG 32
#define CFA_RESTORE_REGNO 31
#else
// 32 bit ARM is not yet supported
#define IPREG 15
#define CFA_RESTORE_REGNO 13
#endif

#endif

// Many platforms will have a 128-bit SIMD register that can be treated as 2
// doubles or 4 floats, 4 integers, etc. Create a specific type for it. By
// "many platforms", I mean this fits x86_64 XMM registers well, and maybe the
// ARM fpsimd ones. Also, note that i386 has access to these, but not the
// 128-bit fields

union i387Float {
   unsigned int i[4];
   long double ld;
};

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
};

// This is for MMX.
union Simd64 {
   int8_t i8[16];
   uint8_t u8[16];
   int16_t i16[8];
   uint16_t u16[8];
   int32_t i32[4];
   uint32_t u32[4];
   int64_t i64[2];
   uint64_t u64[2];
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
   i387Float,
   Simd64,
   Simd128,
#ifndef __i386__
   __uint128_t,
   __int128_t,
#endif
   char
      >;

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
using DwarfNames = std::vector<std::pair<int, std::string_view>>;

// Sets of registers for an architecture. Each architecture supports at least
// "general" registers.
using ArchRegs = std::unordered_map<std::string_view, DwarfNames>;
extern const ArchRegs registers;

#ifndef __aarch64__
void gregset2user(user_regs_struct &core, const gregset_t greg);
#endif

struct Get {
   template <typename T> using Val  = T;
   template <typename T> using Reg  = const T;
};

struct Set {
   template <typename T> using Val  = const T;
   template <typename T> using Reg  = T;
};

template <typename T>
inline void regop(Set, T &reg, const T &val) { reg = val; }
template <typename T>
inline void regop(Get, const T &reg, T &val) { val = reg; }

template <typename T> void regop(Set, T &reg, const RegisterValue &val) {
   regop(Set{}, reg, std::get<T>(val));
}
template <typename T> void regop(Get, const T &reg, RegisterValue &val) {
   T newval;
   regop(Get{}, reg, newval);
   val = newval;
}

inline void regop(Set, Simd128 &simd, const RegisterValue &v) {
   std::memcpy((void *)&simd, (void *)&std::get<Simd128>(v), sizeof simd);
}

inline void regop(Get, const Simd128 &simd, RegisterValue &v) {
   v = Simd128{};
   std::memcpy((void *)&std::get<Simd128>(v), (void *)&simd, sizeof simd);
}

inline void regop(Set, i387Float &simd, const RegisterValue &v) {
   std::memcpy((void *)&simd, (void *)&std::get<i387Float>(v), sizeof simd);
}

inline void regop(Get, const i387Float &simd, RegisterValue &v) {
   v = i387Float{};
   std::memcpy((void *)&std::get<i387Float>(v), (void *)&simd, sizeof simd);
}


inline void regop(Set, Simd64 &simd, const RegisterValue &v) {
   std::memcpy((void *)&simd, (void *)&std::get<Simd64>(v), sizeof simd);
}

inline void regop(Get, const Simd64 &simd, RegisterValue &v) {
   v = Simd64{};
   std::memcpy((void *)&std::get<Simd64>(v), (void *)&simd, sizeof simd);
}




}
#endif
