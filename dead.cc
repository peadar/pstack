#include <iostream>
#include "elfinfo.h"
#include "dwarf.h"
#include "procinfo.h"

CoreProcess::CoreProcess(Reader &exe, Reader &coreFile)
    : Process(exe, coreIO)
    , coreImage(coreFile)
    , coreIO(this)
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


std::string CoreReader::describe() const
{
    std::ostringstream os;
    os << "process loaded from core " << p->coreImage.io;
    return os.str();
}

size_t
CoreReader::read(off_t remoteAddr, size_t size, char *ptr) const
{
    off_t cur = remoteAddr;
    /* Locate "remoteAddr" in the core file */
    while (size) {
        auto obj = &p->coreImage;
        Elf_Off reloc = 0;

        // Check the corefile first.
        auto hdr = obj->findHeaderForAddress(cur);

        if (hdr == 0) {
            // Not in the corefile - but loaded libs may contain unmodified data
            // not copied into the core - check through those.
            for (auto &i : p->objects) {
                reloc = i.first;
                hdr = i.second->findHeaderForAddress(cur - reloc);
                if (hdr) {
                    obj = i.second;
                    break;
                }
            }
            if (hdr == 0) {
                if (cur == remoteAddr)
                    throw Exception() << "no mapping for address " << std::hex << cur << " after " << (cur - remoteAddr);
                break;
            }
        }
        Elf_Addr objAddr = cur - reloc;
        Elf_Off fragSize = std::min(Elf_Off(hdr->p_vaddr + hdr->p_memsz - objAddr), Elf_Off(size));
        size_t rv = obj->io.read(hdr->p_offset + objAddr - hdr->p_vaddr, fragSize, ptr);
        if (rv == 0)
            break;
        size -= rv;
        cur += rv;
    }
    return cur - remoteAddr;
}

CoreReader::CoreReader(CoreProcess *p_) : p(p_) { }

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


