#include <iostream>
#include "elfinfo.h"
#include "dwarf.h"
#include "procinfo.h"

struct PIDFinder {
    const Process *p;
    pid_t pid;
};
static enum NoteIter
getPidFromNote(void *cookie, const char *name, u_int32_t type, const void *datap, size_t len)
{
    if (type == NT_PRSTATUS) {
        PIDFinder *pf = (PIDFinder *)cookie;
        const prstatus_t *status = (const prstatus_t *)datap;
        pf->pid = status->pr_pid;
        return NOTE_DONE;
    }
    return NOTE_CONTIN;
}

CoreProcess::CoreProcess(Reader &exe, Reader &coreFile)
    : Process(exe)
    , coreImage(coreFile)
{
}

void
CoreProcess::load()
{
#ifdef __linux__
    /* Find the linux-gate VDSO, and treat as an ELF file */
    coreImage.getNotes(
        [] (void *cookie, const char *name, u_int32_t type, const void *datap, size_t len) {
            if (type == NT_AUXV) {
                static_cast<CoreProcess *>(cookie)->addVDSOfromAuxV(datap, len);
                return NOTE_DONE;
            }
            return NOTE_CONTIN;
        }, this);
#endif
    Process::load();
}

void
CoreProcess::read(off_t remoteAddr, size_t size, char *ptr) const
{
    size_t readLen = 0;
    /* Locate "remoteAddr" in the core file */
    while (size) {
        auto obj = &coreImage;
        auto hdr = obj->findHeaderForAddress(remoteAddr);
        if (hdr == 0)
            for (auto o : objectList) {
                hdr = o->findHeaderForAddress(remoteAddr);
                if (hdr) {
                    obj = o;
                    break;
                }
            }
        if (hdr == 0)
            throw 999;
        Elf_Addr addr = obj->addrProc2Obj(remoteAddr);
        size_t fragSize = std::min(hdr->p_vaddr + hdr->p_memsz - remoteAddr, size);
        obj->io.readObj(hdr->p_offset + addr - hdr->p_vaddr, ptr, fragSize);
        size -= fragSize;
        readLen += fragSize;
    }
}

/* Callback data for procRegsFromNote */
struct RegnoteInfo {
    const Process *proc;
    lwpid_t pid;
    CoreRegisters *reg;
};

static enum NoteIter
regsFromNote(void *cookie, const char *name, u_int32_t type,
    const void *data, size_t len)
{
    const prstatus_t *prstatus;
    struct RegnoteInfo *rni;
    prstatus = (const prstatus_t *)data;
    rni = (RegnoteInfo *)cookie;
    if (type == NT_PRSTATUS && prstatus->pr_pid == rni->pid) {
        memcpy(rni->reg, (const DwarfRegisters *)&prstatus->pr_reg, sizeof(*rni->reg));
        return (NOTE_DONE);
    }
    return (NOTE_CONTIN);
}
 
bool
CoreProcess::getRegs(lwpid_t pid, CoreRegisters *reg) const
{
    struct RegnoteInfo rni;
    rni.proc = this;
    rni.pid = pid;
    rni.reg = reg;
    return coreImage.getNotes(regsFromNote, &rni) == 0;
}

void
CoreProcess::resume(pid_t) const
{
    // can't resume post-mortem debugger.
}

void
CoreProcess::stop(lwpid_t pid) const
{
    // can't stop a dead process.
}
pid_t
CoreProcess::getPID() const
{
    PIDFinder pf;
    pf.p = this;
    pf.pid = -1;
    coreImage.getNotes(getPidFromNote, &pf);
    std::clog << "got pid: " << pf.pid << std::endl;
    return pf.pid;
}


