#include "libpstack/go.h"
#include "libpstack/proc.h"

#include <limits>

namespace pstack::Procman {

// per-platform definitions for GREG and CTXTREG (Go's "g" and "ctxt" registers)
#if defined(__x86_64__)
#define GREG 14 // "r14"
#define CTXTREG 1 // "rdx"
#elif defined(__i386__)
#define CTXTREG 2 // "edx"
#elif defined(__aarch64__)
#define GREG 28
#define CTXTREG 26
#elif defined(__arm__)
#define CTXTREG 7
#endif

void
addGoRoutines(Process &proc, Stacks &stacks)
{
    Elf::Object::sptr elf;
    Elf::Addr loadAddress;
    Elf::Sym allgsSymbol;
    try {
        std::tie(elf, loadAddress, allgsSymbol) = proc.resolveSymbolDetail("runtime.allgs", true);
    }
    catch (const Exception &ex) {
        // Most targets are not Go programs; absence of this runtime symbol is normal.
        if (proc.context.verbose > 1)
            *proc.context.debug << "no go interpreter detected: " << ex.what() << "\n";
        return;
    }

    try {
        const auto &offsets = Go::getOffsets(proc.context, *elf);
        const Elf::Addr allgsAddress = loadAddress + allgsSymbol.st_value;
        const Elf::Addr allgsData = proc.io->readObj<Elf::Addr>(allgsAddress + offsets.allgsData);
        const Elf::Addr count = proc.io->readObj<Elf::Addr>(allgsAddress + offsets.allgsLength);
        if (!allgsData || !count)
            return;
        if (count > 1'000'000)
            throw Exception() << "runtime.allgs has implausible length " << count;

        lwpid_t fakeLWPId = -1;

        for (Elf::Addr i = 0; i < count; ++i) {
            try {
                auto g = proc.io->readObj<Elf::Addr>(allgsData + i * offsets.allgsStride);
                if (!g)
                    continue;
                const Elf::Addr sched = g + offsets.gSched;

                // Running goroutines have their state in a kernel thread. A nonzero
                // saved SP identifies goroutines parked in the runtime scheduler.
                auto sp = proc.io->readObj<Elf::Addr>(sched + offsets.gobufSp);
                if (!sp)
                    continue;
                auto pc = proc.io->readObj<Elf::Addr>(sched + offsets.gobufPc);
                if (!pc)
                    continue;
                auto goid = proc.io->readObj<uint64_t>(g + offsets.gGoid);
                if (!goid)
                    continue; // g0 and gsignal are runtime scheduler stacks.

                CoreRegisters regs{};
                regs.setDwarf(SPREG, RegisterValue{gpreg(sp)});
                regs.setDwarf(IPREG, RegisterValue{gpreg(pc)});
                if (offsets.gobufBp) {
                    const Elf::Addr bp = proc.io->readObj<Elf::Addr>(sched + *offsets.gobufBp);
                    regs.setDwarf(BPREG, RegisterValue{gpreg(bp)});
                }
#ifdef GREG
                if (offsets.gobufG) {
                    const Elf::Addr g = proc.io->readObj<Elf::Addr>(sched + *offsets.gobufG);
                    regs.setDwarf(GREG, RegisterValue{gpreg(g)});
                }
#endif
#ifdef CTXTREG
                if (offsets.gobufCtxt) {
                    const Elf::Addr ctxt = proc.io->readObj<Elf::Addr>(sched + *offsets.gobufCtxt);
                    regs.setDwarf(CTXTREG, RegisterValue{gpreg(ctxt)});
                }
#endif
#ifdef LRREG
                if (offsets.gobufLr) {
                    const Elf::Addr lr = proc.io->readObj<Elf::Addr>(sched + *offsets.gobufLr);
                    regs.setDwarf(LRREG, RegisterValue{gpreg(lr)});
                }
#endif
                Lwp goroutine;
                goroutine.id = fakeLWPId--;
                goroutine.goroutineID = goid;
                goroutine.unwind(proc, regs);
                stacks.emplace(goroutine.id, std::move(goroutine));
            }
            catch (const Exception &ex) {
                if (proc.context.verbose > 1)
                    *proc.context.debug << "failed to unwind Go goroutine " << i << ": " << ex.what() << "\n";
            }
        }
    }
    catch (const Exception &ex) {
        if (proc.context.verbose > 0)
            *proc.context.debug << "Go goroutine support unavailable: " << ex.what() << "\n";
    }
}

} // namespace pstack::Procman
