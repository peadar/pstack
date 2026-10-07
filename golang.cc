#include "libpstack/go.h"
#include "libpstack/proc.h"

#include <algorithm>
#include <fstream>
#include <limits>


namespace pstack::Go {
void
Go::RuntimeOffsets::parse(std::istream &in) {
    Go::RuntimeOffsets offsets;

    // map from key to function to set the content in offsets. The bool is
    // whether this field is mandatory. We remove each field as we parse it, so
    // if there are any mandatory ones left at the end, it's an error.
    //
    std::map<std::string_view, std::pair<bool, std::function<void()>>> m = {
        { "version", {true, [&]() { version = parseString(in); } }},
        { "machine", {true, [&]() { machine = parseInt<Elf::Half>(in); } }},
        { "pointer_size", {true, [&]() { pointerSize = parseInt<size_t>(in); } }},
        { "allgs_data", {true, [&]() { allgsData = parseInt<uintmax_t>(in); } }},
        { "allgs_length", {true, [&]() { allgsLength = parseInt<uintmax_t>(in); } }},
        { "allgs_stride", {true, [&]() { allgsStride = parseInt<uintmax_t>(in); } }},
        { "g_size", {true, [&]() { gSize = parseInt<uintmax_t>(in); } }},
        { "g_sched", {true, [&]() { gSched = parseInt<uintmax_t>(in); } }},
        { "g_goid", {true, [&]() { gGoid = parseInt<uintmax_t>(in); } }},
        { "gobuf_sp", {true, [&]() { gobufSp = parseInt<uintmax_t>(in); } }},
        { "gobuf_pc", {true, [&]() { gobufPc = parseInt<uintmax_t>(in); } }},
        { "gobuf_bp", {false, [&]() { gobufBp = parseInt<uintmax_t>(in); } }},
        { "gobuf_g", {false, [&]() { gobufG = parseInt<uintmax_t>(in); } }},
        { "gobuf_ctxt", {false, [&]() { gobufCtxt = parseInt<uintmax_t>(in); } }},
        { "gobuf_lr", {false, [&]() { gobufLr = parseInt<uintmax_t>(in); } }},
    };

    parseObject(in, [&](std::istream &is, std::string field) {
            auto node = m.extract(field);
            if (node) {
                node.mapped().second();
            } else {
                parseValue(is);
            }});

    if (std::any_of(m.begin(), m.end(), [](const auto value) { return value.second.second; } ) ) {
        throw Exception() << "missing go fields";
    }
}

}


namespace pstack::Procman {
namespace {

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

Go::RuntimeOffsets
loadOffsets(Process &proc, const std::string &version, Elf::Half machine)
{
    const auto fileName = Go::offsetFileName(version, machine);
    for (const auto &directory : findXdgDataDirs()) {
        auto path = directory / fileName;
        std::ifstream in(path);
        if (!in)
            continue;
        Go::RuntimeOffsets offsets;
        offsets.parse(in);
        if (Go::versionSeries(offsets.version) != Go::versionSeries(version) ||
                offsets.machine != machine)
            throw Exception() << "Go offset data in " << path << " does not match its filename";
        if (offsets.pointerSize != sizeof(Elf::Addr))
            throw Exception() << "Go offset data in " << path << " has the wrong pointer size";
        if (proc.context.verbose)
            *proc.context.debug << "found Go offsets data in " << path << "\n";
        return offsets;
    }
    throw Exception() << "cannot find '" << fileName << "' - run pstack-mkgooff on a Go executable built with this Go version";
}

} // namespace

void
addGoRoutines(Process &proc, Stacks &stacks)
{
    Elf::Object::sptr elf;
    Elf::Addr loadAddress;
    Elf::Sym allgsSymbol;
    try {
        std::tie(elf, loadAddress, allgsSymbol) =
            proc.resolveSymbolDetail("runtime.allgs", true);
    }
    catch (const Exception &) {
        // Most targets are not Go programs; absence of this runtime symbol is normal.
        return;
    }

    try {
        const std::string goVersion = Go::version(*elf);
        const auto offsets = loadOffsets(proc, goVersion, elf->getHeader().e_machine);
        const Elf::Addr allgsAddress = loadAddress + allgsSymbol.st_value;
        const Elf::Addr allgsData = proc.io->readObj<Elf::Addr>(allgsAddress + offsets.allgsData);
        const Elf::Addr count = proc.io->readObj<Elf::Addr>(allgsAddress + offsets.allgsLength);
        if (count > 1'000'000)
            throw Exception() << "runtime.allgs has implausible length " << count;
        if (!allgsData || !count)
            return;

        lwpid_t syntheticID = std::numeric_limits<lwpid_t>::min();
        for (Elf::Addr i = 0; i < count; ++i) {
            try {
                const Elf::Addr g = proc.io->readObj<Elf::Addr>(allgsData + i * offsets.allgsStride);
                if (!g)
                    continue;
                const Elf::Addr sched = g + offsets.gSched;

                // Running goroutines have their state in a kernel thread. A nonzero
                // saved SP identifies goroutines parked in the runtime scheduler.
                const Elf::Addr sp = proc.io->readObj<Elf::Addr>(sched + offsets.gobufSp);
                if (!sp)
                    continue;
                const Elf::Addr pc = proc.io->readObj<Elf::Addr>(sched + offsets.gobufPc);
                if (!pc)
                    continue;
                const uint64_t goid = proc.io->readObj<uint64_t>(g + offsets.gGoid);
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
                goroutine.id = syntheticID++;
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
