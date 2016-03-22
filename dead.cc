#include <iostream>
#include "elfinfo.h"
#include "dwarf.h"
#include "procinfo.h"

CoreProcess::CoreProcess(
        std::shared_ptr<ElfObject> exe,
        std::shared_ptr<ElfObject> core,
        const PathReplacementList &pathReplacements_)
    : Process(exe, std::make_shared<CoreReader>(this), pathReplacements_)
    , coreImage(core)
{
}

struct NotesCb {
    CoreProcess *cp;
    NotesCb(CoreProcess *cp_) : cp(cp_) {}
    NoteIter operator()(const char *, u_int32_t, const void *, size_t) const;
};

NoteIter
NotesCb::operator()(const char *name, u_int32_t type, const void *datap, size_t len) const
{
#ifdef NT_AUXV
    if (strcmp(name, "CORE") == 0 && type == NT_AUXV) {
        cp->processAUXV(datap, len);
        return NOTE_DONE;
    }
#endif
    return NOTE_CONTIN;
}

void
CoreProcess::load()
{
#ifdef __linux__
    NotesCb cb(this);
    /* Find the linux-gate VDSO, and treat as an ELF file */
    coreImage->getNotes(cb);
#endif
    Process::load();
}


std::string CoreReader::describe() const
{
    return p->coreImage->io->describe();
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
        auto hdr = obj->findHeaderForAddress(remoteAddr);
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
            hdr = i->object->findHeaderForAddress(remoteAddr - i->reloc);
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

struct RegCallback {
    lwpid_t pid;
    CoreRegisters *reg;
    NoteIter operator()(const char *name, u_int32_t type, const void *data, size_t) const {
        const prstatus_t *prstatus = (const prstatus_t *)data;
#ifdef NT_PRSTATUS
        if (strcmp(name, "CORE") == 0 && type == NT_PRSTATUS && prstatus->pr_pid == pid) {
            memcpy(reg, (const DwarfRegisters *)&prstatus->pr_reg, sizeof(*reg));
            return (NOTE_DONE);
        }
#endif
        return NOTE_CONTIN;
    }
    RegCallback(lwpid_t pid_, CoreRegisters *reg_) : pid(pid_), reg(reg_) {}
};

bool
CoreProcess::getRegs(lwpid_t pid, CoreRegisters *reg) const
{
    RegCallback rc(pid, reg);
    coreImage->getNotes(rc);
    return true;
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

struct PidCallback {
    mutable pid_t pid;
    NoteIter operator()(const char *name, u_int32_t type, const void *data, size_t) const {
#ifdef NT_PRSTATUS
        if (strcmp(name, "CORE") == 0 && type == NT_PRSTATUS) {
            const prstatus_t *status = (const prstatus_t *)data;
            pid = status->pr_pid;
            return NOTE_DONE;
        }
#endif
        return NOTE_CONTIN;
    }
};




pid_t
CoreProcess::getPID() const
{
    PidCallback cb;
    coreImage->getNotes(cb);
    if (debug) *debug << "got pid: " << cb.pid << std::endl;
    return cb.pid;
}


