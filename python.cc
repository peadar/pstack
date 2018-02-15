#include <iostream>
#include <stdlib.h>
#include <stddef.h>
#include <libpstack/dwarf.h>
#include <libpstack/proc.h>
#include <python2.7/Python.h>
#include <python2.7/frameobject.h>

static bool
pthreadTidOffset(const Process &proc, size_t *offsetp)
{
    static size_t offset;
    static enum { notDone, notFound, found } status;
    if (status == notDone) {
        try {
            auto addr = proc.findNamedSymbol(0, "_thread_db_pthread_tid");
            uint32_t desc[3];
            proc.io->readObj(addr, &desc[0], 3);
            offset = desc[2];
            status = found;
            if (verbose)
                *debug << "found thread offset " << offset <<  "\n";
        } catch (const std::exception &ex) {
           if (verbose)
               *debug << "failed to find offset of tid in pthread: " << ex.what();
            status = notFound;
        }
    }
    if (status == found) {
        *offsetp = offset;
        return true;
    }
    return false;
}

// This reimplements PyCode_Addr2Line
int getLine(Process *proc, const PyCodeObject *code, const PyFrameObject *frame)
{
    PyVarObject lnotab;
    proc->io->readObj(Elf_Addr(code->co_lnotab), &lnotab);
    unsigned char linedata[lnotab.ob_size];
    proc->io->readObj(Elf_Addr(code->co_lnotab) + offsetof(PyStringObject, ob_sval),
            &linedata[0], lnotab.ob_size);
    int line = code->co_firstlineno;
    int addr = 0;
    unsigned char *p = linedata;
    unsigned char *e = linedata + lnotab.ob_size;
    while (p < e) {
        addr += *p++;
        if (addr > frame->f_lasti) {
            break;
        }
        line += *p++;
    }
    return line;
}

/*
 * process one python thread in an interpreter, at remote addr "ptr". 
 * returns the address of the next thread on the list.
 */
Elf_Addr
doPyThread(Process &proc, std::ostream &os, Elf_Addr ptr)
{
    PyThreadState thread;
    proc.io->readObj(ptr, &thread);
    PyFrameObject frame;

    size_t toff;
    if (thread.thread_id && pthreadTidOffset(proc, &toff)) {
        Elf_Addr tidptr = thread.thread_id + toff;
        pid_t tid;
        proc.io->readObj(tidptr, &tid);
        os << "pthread: 0x" << std::hex << thread.thread_id << std::dec << ", lwp " << tid;
    } else {
       os << "anonymous thread";
    }
    os << "\n";
    for (auto framePtr = Elf_Addr(thread.frame); framePtr != 0; framePtr = Elf_Addr(frame.f_back)) {
        proc.io->readObj(framePtr, &frame);
        PyCodeObject code;
        proc.io->readObj(Elf_Addr(frame.f_code), &code);
        auto lineNo = getLine(&proc, &code, &frame);
        auto func = proc.io->readString(Elf_Addr(code.co_name) + offsetof(PyStringObject, ob_sval));
        auto file = proc.io->readString(Elf_Addr(code.co_filename) + offsetof(PyStringObject, ob_sval));
        os << "\t" << func << " in " << file << ":" << lineNo << "\n";
    }
    return Elf_Addr(thread.next);
}

/*
 * Process one python interpreter in the process at remote address ptr
 * Returns the address of the next interpreter on on the process's list.
 */
Elf32_Addr
doPyInterp(Process &proc, std::ostream &os, Elf_Addr ptr)
{
    PyInterpreterState state;
    proc.io->readObj(ptr, &state);
    os << "---- interpreter @" << std::hex << ptr << std::dec << " -----" << std::endl ;
    for (Elf_Addr tsp = reinterpret_cast<Elf_Addr>(state.tstate_head); tsp; ) {
        tsp = doPyThread(proc, os, tsp);
        os << std::endl;
    }
    return reinterpret_cast<Elf_Addr>(state.next);
}

/*
 * Print all python stack traces from this process.
 */
std::ostream &
pythonStack(Process &proc, std::ostream &os, const PstackOptions &)
{
    // Find the python library.
    for (auto &o : proc.objects) {
        std::string module = stringify(*o.object->io);
        if (module.find("python") == std::string::npos)
            continue;
        auto dwarf = proc.imageCache.getDwarf(ElfObject::getDebug(o.object));
        if (!dwarf)
            continue;
        for (auto u : dwarf->getUnits()) {
            // For each unit
            for (const DwarfEntry *compile : u->entries) {
                if (compile->type->tag != DW_TAG_compile_unit)
                    continue;
                // Do we have a global variable called interp_head?
                for (const DwarfEntry *var : compile->children) {
                    if (var->type->tag != DW_TAG_variable)
                        continue;
                    if (var->name() != "interp_head")
                        continue;
                    // Yes - let's run through the interpreters, and dump their stacks.
                    DwarfExpressionStack evalStack;
                    auto addr = evalStack.eval(proc, var->attrForName(DW_AT_location), 0, o.reloc);
                    Elf_Addr ptr;
                    for (proc.io->readObj(addr, &ptr); ptr; )
                        ptr = doPyInterp(proc, os, ptr);
                }
            }
        }
    }
    return os;
}
