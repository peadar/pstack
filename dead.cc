#include <iostream>
#include "libpstack/elf.h"
#include "libpstack/dwarf.h"
#include "libpstack/proc.h"

CoreProcess::CoreProcess(
        std::shared_ptr<ElfObject> exe,
        std::shared_ptr<ElfObject> core,
        const PathReplacementList &pathReplacements_,
        DwarfImageCache &imageCache
        )
    : Process(exe, std::make_shared<CoreReader>(this), pathReplacements_, imageCache)
    , coreImage(core)
{
}

void
CoreProcess::load()
{
#ifdef __linux__
    /* Find the linux-gate VDSO, and treat as an ELF file */
    for (auto note : coreImage->notes) {
       if (note.name() == "CORE" && note.type() == NT_AUXV) {
           processAUXV(note.data(), note.size());
           break;
       }
    }
#endif
    Process::load();
}

void CoreReader::describe(std::ostream &os) const
{
    os << *p->coreImage->io;
}

static size_t
readFromHdr(std::shared_ptr<ElfObject> obj, const Elf_Phdr *hdr, Elf_Off addr, char *ptr, Elf_Off size, Elf_Off *toClear)
{
    Elf_Off rv, off = addr - hdr->p_vaddr; // offset in header of our ptr.
    if (off < hdr->p_filesz) {
        // some of the data is in the file: read min of what we need and // that.
        Elf_Off fileSize = std::min(hdr->p_filesz - off, size);
        rv = obj->io->read(hdr->p_offset + off, fileSize, ptr);
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
        auto obj = p->coreImage;

        Elf_Off zeroes = 0;
        // Locate "remoteAddr" in the core file
        auto hdr = obj->getSegmentForAddress(remoteAddr);
        if (hdr) {
            // The start address appears in the core (or is defaulted from it)
            size_t rc = readFromHdr(obj, hdr, remoteAddr, ptr, size, &zeroes);
            remoteAddr += rc;
            ptr += rc;
            size -= rc;
            if (rc && zeroes == 0) // we got some data from the header, and there's nothing to default
                continue;
        }

        // Either no data in core, or it was incomplete to this point: search loaded objects.
        hdr = 0;
        obj.reset();
        Elf_Off reloc;
        for (auto i = p->objects.begin(); i != p->objects.end(); ++i) {
            hdr = i->object->getSegmentForAddress(remoteAddr - i->reloc);
            if (hdr) {
                obj = i->object;
                reloc = i->reloc;
                break;
            }
        }

        if (hdr) {
            // header in an object - try reading from here.
            size_t rc = readFromHdr(obj, hdr, remoteAddr - reloc, ptr, size, &zeroes);
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
CoreProcess::getRegs(lwpid_t pid, CoreRegisters *reg)
{
   for (auto note : coreImage->notes) {
        const prstatus_t *prstatus = (const prstatus_t *)note.data();
#ifdef NT_PRSTATUS
        if (note.name() == "CORE" && note.type() == NT_PRSTATUS && prstatus->pr_pid == pid) {
            memcpy(reg, &prstatus->pr_reg, sizeof(*reg));
            return true;
        }
#endif
   }
   return false;
}

void
CoreProcess::resume(pid_t)
{
    // can't resume post-mortem debugger.
}

void
CoreProcess::stop(lwpid_t)
{
    // can't stop a dead process.
}

pid_t
CoreProcess::getPID() const
{
    for (auto note : coreImage->notes) {
        if (note.name() == "CORE" && note.type() == NT_PRSTATUS) {
            const prstatus_t *status = (const prstatus_t *)note.data();
            return status->pr_pid;
        }
    }
    return -1;
}
