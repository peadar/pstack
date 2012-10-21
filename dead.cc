#include <iostream>
#include "elfinfo.h"
#include "dwarf.h"
#include "procinfo.h"

CoreProcess::CoreProcess(ElfObject *exe, Reader &coreFile, std::ostream *debug)
    : Process(exe, coreIO, debug)
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
    return p->coreImage.io.describe();
}

static size_t
readFromHdr(ElfObject *obj, const Elf_Phdr *hdr, Elf_Off addr, Elf_Off reloc, char *ptr, size_t size, size_t *toClear)
{
    Elf_Off off = addr - reloc - hdr->p_vaddr; // offset in header of our ptr.
    size_t rv;
    if (off < hdr->p_filesz) {
        // some of the data is in the file: read min of what we need and // that.
        Elf_Off fileSize = std::min(hdr->p_filesz - off, size);
        rv = obj->io.read(hdr->p_offset + off, fileSize, ptr);
        if (rv != fileSize)
            throw Exception() << "unexpected short read in core file";
        off += rv;
        size -= rv;
    } else {
        rv = 0;
    }
    if (toClear)
        *toClear = std::max(
            *toClear > rv
                ? *toClear - rv
                : 0,
            size != 0 && off < hdr->p_memsz
                ?  std::min(size, hdr->p_memsz - off)
                : 0);
    return rv;
}

size_t
CoreReader::read(off_t remoteAddr, size_t size, char *ptr) const
{
    Elf_Off start = remoteAddr;
    while (size) {
        auto obj = &p->coreImage;

        size_t zeroes = 0;
        // Locate "remoteAddr" in the core file
        auto hdr = obj->findHeaderForAddress(remoteAddr);
        if (hdr) {
            // The start address appears in the core (or is defaulted from it)
            size_t rc = readFromHdr(obj, hdr, remoteAddr, 0, ptr, size, &zeroes);
            remoteAddr += rc;
            ptr += rc;
            size -= rc;
            if (rc && zeroes == 0) // we got some data from the header, and there's nothing to default
                continue;
        }

        // Either no data in core, or it was incomplete to this point: search loaded objects.
        hdr = 0;
        obj = 0;
        Elf_Off reloc;
        for (auto &i : p->objects) {
            reloc = i.first;
            hdr = i.second->findHeaderForAddress(remoteAddr - reloc);
            if (hdr) {
                obj = i.second;
                reloc = i.first;
                break;
            }
        }

        if (hdr) {
            // header in an object - try reading from here.
            size_t rc = readFromHdr(obj, hdr, remoteAddr, reloc, ptr, size, &zeroes);
            remoteAddr += rc;
            ptr += rc;
            size -= rc;
        }

        // At this point, we have copied any real data, and "zeroes" reflects
        // the amount we can default to zero.
        memset(ptr, 0, zeroes);
        size -= zeroes;
        remoteAddr += zeroes;
        ptr += zeroes;
        
        if (hdr == 0 && zeroes == 0) // Nothing from core, objects, or defaulted. We're stuck.
            break;
    }
    return remoteAddr - start;
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


