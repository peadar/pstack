#include <iostream>
#include "elfinfo.h"
#include "dwarf.h"
#include "procinfo.h"

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
        [this] (const char *name, u_int32_t type, const void *datap, size_t len) {
            if (type == NT_AUXV) {
                this->processAUXV(datap, len);
                return NOTE_DONE;
            }
            return NOTE_CONTIN;
        });
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

        // Check the corefile first.
        auto hdr = obj->findHeaderForAddress(remoteAddr);
        if (hdr == 0)
            // Not in the corefile - but loaded libs may contain unmodified data
            // not copied into the core - check through those.
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
        Elf_Off fragSize = std::min(Elf_Off(hdr->p_vaddr + hdr->p_memsz - remoteAddr), Elf_Off(size));
        obj->io.readObj(hdr->p_offset + addr - hdr->p_vaddr, ptr, fragSize);
        size -= fragSize;
        readLen += fragSize;
    }
}

bool
CoreProcess::getRegs(lwpid_t pid, CoreRegisters *reg) const
{
    coreImage.getNotes(
        [reg, pid] (const char *name, u_int32_t type, const void *data, size_t len) -> NoteIter {
            const prstatus_t *prstatus = (const prstatus_t *)data;
            if (type == NT_PRSTATUS && prstatus->pr_pid == pid) {
                memcpy(reg, (const DwarfRegisters *)&prstatus->pr_reg, sizeof(*reg));
                return (NOTE_DONE);
            }
            return NOTE_CONTIN;
        });
    return true;
}
    
void
CoreProcess::resume(pid_t)
{
    // can't resume post-mortem debugger.
}

void
CoreProcess::stop(lwpid_t pid)
{
    // can't stop a dead process.
}

pid_t
CoreProcess::getPID() const
{
    pid_t pid;
    coreImage.getNotes([this, &pid] (const char *name, u_int32_t type, const void *datap, size_t len) {
        if (type == NT_PRSTATUS) {
            const prstatus_t *status = (const prstatus_t *)datap;
            pid = status->pr_pid;
            return NOTE_DONE; }
        return NOTE_CONTIN;
    });
    std::clog << "got pid: " << pid << std::endl;
    return pid;
}


