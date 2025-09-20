#define USER_REGS(core) core.user
#if defined( __i386__ )
#define IPREG 8
#define CFA_RESTORE_REGNO 4
#elif defined( __amd64__ )
#define FP_REGS(core) core.fp
#define CFA_RESTORE_REGNO 7
#define IPREG 16
#elif defined( __ARM_ARCH )
#if ELF_BITS == 32
#define IPREG 15
#define CFA_RESTORE_REGNO 13
#else
#define FP_REGS(core) core.fpsimd
#define IPREG 32
#define CFA_RESTORE_REGNO 31
#endif
#endif
