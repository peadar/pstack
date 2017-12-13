#include <iostream>
#include <stddef.h>
#include <libpstack/dwarf.h>
#include <libpstack/proc.h>
#include <python2.7/Python.h>
#include <python2.7/frameobject.h>

Elf_Addr
doPyThread(Process &proc, std::ostream &os, Elf_Addr ptr)
{
    PyThreadState thread;
    proc.io->readObj(ptr, &thread);
    PyFrameObject frame;

    os << "\tthread @" << std::hex << ptr << std::dec;
    if (thread.thread_id) {
       // XXX: offsets for pid/tid came from debugging in gdb. They are almost
       // certainly wrong for 64-bit, and liable to change. The structure required
       // to find the canonical version is pthread, defined in nptl/descr.h in
       // the libc source.
       Elf_Addr pidptr = thread.thread_id + sizeof (pid_t) * 26;
       pid_t pids[2];
       proc.io->readObj(pidptr, &pids[0], 2);
       os << " lwp " << pids[0] << ", pid " << pids[1];
    }
    os << "\n";
    for (auto framePtr = Elf_Addr(thread.frame); framePtr != 0; framePtr = Elf_Addr(frame.f_back)) {
        proc.io->readObj(framePtr, &frame);
        PyCodeObject code;
        proc.io->readObj(Elf_Addr(frame.f_code), &code);
        auto func = proc.io->readString(Elf_Addr(code.co_name) + offsetof(PyStringObject, ob_sval));
        auto file = proc.io->readString(Elf_Addr(code.co_filename) + offsetof(PyStringObject, ob_sval));
        os << "\t\t" << func << " in " << file << ":" << frame.f_lineno << "\n";
    }
    return Elf_Addr(thread.next);
}

Elf32_Addr
doPyInterp(Process &proc, std::ostream &os, Elf_Addr ptr)
{
    PyInterpreterState state;
    proc.io->readObj(ptr, &state);
    os << "interpreter @" << std::hex << ptr << std::dec << std::endl;
    for (Elf_Addr tsp = reinterpret_cast<Elf_Addr>(state.tstate_head); tsp; ) {
        tsp = doPyThread(proc, os, tsp);
    }
    return reinterpret_cast<Elf_Addr>(state.next);
}

std::ostream &
pythonStack(Process &proc, std::ostream &os, const PstackOptions &)
{
    // Find the python library.
    for (auto &o : proc.objects) {
        std::string module = stringify(*o.object->io);
        if (module.find("python") != std::string::npos) {
            auto dwarf = proc.imageCache.getDwarf(ElfObject::getDebug(o.object));
            if (dwarf) {
                for (auto u : dwarf->getUnits()) {
                    for (const DwarfEntry *compile : u->entries) {
                        if (compile->type->tag == DW_TAG_compile_unit) {
                            for (const DwarfEntry *var : compile->children) {
                                if (var->type->tag == DW_TAG_variable && var->name() == "interp_head") {
                                    DwarfExpressionStack evalStack;
                                    auto addr = evalStack.eval(proc, var->attrForName(DW_AT_location), 0, o.reloc);
                                    Elf_Addr ptr;
                                    for (proc.io->readObj(addr, &ptr); ptr; ) {
                                        ptr = doPyInterp(proc, os, ptr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return os;
}
