#include "libpstack/dwarf.h"
#include "libpstack/elf.h"
#include "libpstack/proc.h"

#include <iostream>

CoreProcess::CoreProcess(Elf::Object::sptr exec, Elf::Object::sptr core,
        const PathReplacementList &pathReplacements_, Dwarf::ImageCache &imageCache)
    : Process(std::move(exec), std::make_shared<CoreReader>(this), pathReplacements_, imageCache)
    , coreImage(std::move(core))
{
}

void
CoreProcess::load(const PstackOptions &options)
{
#ifdef __linux__
    for (auto note : coreImage->notes) {
       if (note.name() == "CORE" && note.type() == NT_AUXV) {
           processAUXV(*note.data());
           break;
       }
    }
#endif
    Process::load(options);
}

void CoreReader::describe(std::ostream &os) const
{
    os << *p->coreImage->io;
}

static size_t
readFromHdr(const Elf::Object &obj, const Elf::Phdr *hdr, Elf::Off addr, char *ptr, Elf::Off size, Elf::Off *toClear)
{
    Elf::Off rv, off = addr - hdr->p_vaddr; // offset in header of our ptr.
    if (off < hdr->p_filesz) {
        // some of the data is in the file: read min of what we need and // that.
        Elf::Off fileSize = std::min(hdr->p_filesz - off, size);
        rv = obj.io->read(hdr->p_offset + off, fileSize, ptr);
        if (rv != fileSize)
            throw (Exception() << "unexpected short read in core file");
        off += rv;
        size -= rv;
    } else {
        rv = 0;
    }
    if (toClear != nullptr)
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
    Elf::Off start = remoteAddr;
    while (size != 0) {
        auto obj = p->coreImage;

        Elf::Off zeroes = 0;
        // Locate "remoteAddr" in the core file
        auto hdr = obj->getSegmentForAddress(remoteAddr);
        if (hdr != nullptr) {
            // The start address appears in the core (or is defaulted from it)
            size_t rc = readFromHdr(*obj, hdr, remoteAddr, ptr, size, &zeroes);
            remoteAddr += rc;
            ptr += rc;
            size -= rc;
            if (rc != 0 && zeroes == 0) // we got some data from the header, and there's nothing to default
                continue;
        }

        // Either no data in core, or it was incomplete to this point: search loaded objects.
        hdr = nullptr;
        obj.reset();
        Elf::Off loadAddr;
        for (auto &candidate : p->objects) {
            hdr = candidate.object->getSegmentForAddress(remoteAddr - candidate.loadAddr);
            if (hdr != nullptr) {
                obj = candidate.object;
                loadAddr = candidate.loadAddr;
                break;
            }
        }

        if (hdr != nullptr) {
            // header in an object - try reading from here.
            size_t rc = readFromHdr(*obj, hdr, remoteAddr - loadAddr, ptr, size, &zeroes);
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

        if (hdr == nullptr && zeroes == 0) // Nothing from core, objects, or defaulted. We're stuck.
            break;
    }
    return remoteAddr - start;
}

CoreReader::CoreReader(CoreProcess *p_) : p(p_) { }

bool
CoreProcess::getRegs(lwpid_t pid, Elf::CoreRegisters *reg)
{
#ifdef NT_PRSTATUS
   for (auto note : coreImage->notes) {
        if (note.name() == "CORE" && note.type() == NT_PRSTATUS) {
            const auto &prstatus = note.data()->readObj<prstatus_t>(0);
            if (prstatus.pr_pid == pid) {
                memcpy(reg, &prstatus.pr_reg, sizeof(*reg));
                return true;
            }
        }
   }
#endif
   return false;
}

void
CoreProcess::resume(pid_t /* unused */)
{
    // can't resume post-mortem debugger.
}

void
CoreProcess::stop(lwpid_t /* unused */)
{
    // can't stop a dead process.
}

void
CoreProcess::stopProcess()
{
    // Find LWPs when we attempt to "stop" the process.
    findLWPs();
}

pid_t
CoreProcess::getPID() const
{
    // Return the PID of the first task in the core.
    for (auto note : coreImage->notes)
        if (note.name() == "CORE" && note.type() == NT_PRSTATUS)
            return note.data()->readObj<prstatus_t>(0).pr_pid;
    return -1;
}

void
CoreProcess::findLWPs()
{
    for (auto note : coreImage->notes) {
        if (note.name() == "CORE" && note.type() == NT_PRSTATUS)
            (void)lwps[note.data()->readObj<prstatus_t>(0).pr_pid];
    }
}
