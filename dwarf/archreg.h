/* Maps from DWARF register numbers to pt_regs fields for each architecture. */
#ifdef __i386__
#if defined(__FreeBSD__)

REGMAP(1, ptr.r_eax)
REGMAP(2, ptr.r_ecx)
REGMAP(3, ptr.r_ebx)
REGMAP(4, ptr.r_esp)
REGMAP(5, ptr.r_ebp)
REGMAP(6, ptr.r_esi)
REGMAP(7, ptr.r_edi)
REGMAP(8, ptr.r_eip)
REGMAP(9, ptr.r_eflags)
REGMAP(10, ptr.r_cs)
REGMAP(11, ptr.r_ss)
REGMAP(12, ptr.r_ds)
REGMAP(13, ptr.r_es)
REGMAP(14, ptr.r_fs)
REGMAP(15, ptr.r_gs)

#elif defined(__linux__)

REGMAP(1, eax)
REGMAP(2, ecx)
REGMAP(3, ebx)
REGMAP(4, esp)
REGMAP(5, ebp)
REGMAP(6, esi)
REGMAP(7, edi)
REGMAP(8, eip)
REGMAP(9, eflags)
REGMAP(10, xcs)
REGMAP(11, xss)
REGMAP(12, xds)
REGMAP(13, xes)
REGMAP(14, xfs)

/* REGMAP(15, ptr.xgs) */
#else
#error "don't grok pt_regs for your system"
#endif

/*
 * GCC doesn't emit code to unwind the SP properly, and DWARF 2 doesn't
 * really give the operations to do it in the general case (in the event
 * the SP isn't stored anywhere on stack.)  The DWARF spec suggests that
 * the CFA is the value of the stack pointer at the call site, so for
 * architectures where this is correct, we define the CFA_RESTORE_REGNO
 * to point to the register that the CFA should be inserted into after the
 * rest of the unwind is carried out.
 */

#define CFA_RESTORE_REGNO 4
#endif


#ifdef __amd64__

REGMAP(0, rax)
REGMAP(1, rdx)
REGMAP(2, rcx)
REGMAP(3, rbx)
REGMAP(4, rsi)
REGMAP(5, rdi)
REGMAP(6, rbp)
REGMAP(7, rsp)
REGMAP(8, r8)
REGMAP(9, r9)
REGMAP(10, r10)
REGMAP(11, r11)
REGMAP(12, r12)
REGMAP(13, r13)
REGMAP(14, r14)
REGMAP(15, r15)
REGMAP(16, rip)
/* floating point regs
REGMAP(17, rxmm0)
REGMAP(18, rxmm1)
REGMAP(19, rxmm2)
REGMAP(20, rxmm3)
REGMAP(21, rxmm4)
REGMAP(22, rxmm5)
REGMAP(23, rxmm6)
REGMAP(24, rxmm7)
REGMAP(25, rxmm8)
REGMAP(26, rxmm9)
REGMAP(27, rxmm10)
REGMAP(28, rxmm11)
REGMAP(29, rxmm12)
REGMAP(30, rxmm13)
REGMAP(31, rxmm14)
REGMAP(32, rxmm15)
REGMAP(33, rst0)
REGMAP(34, rst1)
REGMAP(35, rst2)
REGMAP(36, rst3)
REGMAP(37, rst4)
REGMAP(38, rst5)
REGMAP(39, rst6)
REGMAP(40, rst7)
REGMAP(41, mm0)
REGMAP(42, mm1)
REGMAP(43, mm2)
REGMAP(44, mm3)
REGMAP(45, mm4)
REGMAP(46, mm5)
REGMAP(47, mm6)
REGMAP(48, mm7)
*/
REGMAP(49, eflags)
REGMAP(50, es)
REGMAP(51, cs)
REGMAP(52, ss)
REGMAP(53, ds)
REGMAP(54, fs)
REGMAP(55, gs)
REGMAP(58, fs_base)
REGMAP(59, gs_base)
#define CFA_RESTORE_REGNO 7

#endif
