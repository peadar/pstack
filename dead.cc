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
readFromHdr(const Elf::Object &obj, const Elf::Phdr *hdr, Elf::Off addr,
            char *ptr, Elf::Off size, Elf::Off *toClear)
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
            if (rc != 0 && zeroes == 0)
                // we got some data from the header, and there's nothing to default
                continue;
        }

        // Either no data in core, or it was incomplete to this point: search loaded objects.
        Elf::Off loadAddr;
        std::tie(loadAddr, obj, hdr) = p->findSegment(remoteAddr);
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


// Types for the NT_FILE note.
struct FileNoteHeader {
    Elf::Off count;
    Elf::Off pageSize;
};
struct FileEntry {
    Elf::Off start;
    Elf::Off end;
    Elf::Off fileOff;
};

bool
CoreProcess::loadSharedObjectsFromFileNote()
{
    // If the core is truncated, and we have no access to the link map, we make
    // a guess at what shared libraries are mapped by looking in the NT_FILE
    // note if present.
    for (auto note : coreImage->notes) {
        if (note.name() == "CORE" && note.type() == NT_FILE) {
            auto data = note.data();
            FileNoteHeader header;
            data->readObj(0, &header);
            Elf::Off stroff = 0;
            auto entries = std::make_shared<OffsetReader>(data, sizeof header, header.count * sizeof (FileEntry));
            auto fileNames = std::make_shared<OffsetReader>(data, sizeof header + header.count * sizeof (FileEntry));
            uintptr_t totalSize = 0;
            for (auto entry : ReaderArray<FileEntry>(*entries)) {
                auto name = fileNames->readString(stroff);
                stroff += name.size() + 1;
                uintptr_t size = entry.end - entry.start;
                totalSize += size;
                if (verbose > 2)
                    *debug << "NT_FILE mapping " << name << " " << (void *)entry.start << " " << size << std::endl;
                if (entry.fileOff == 0) {
                    try {
                        // Just try and load it like an ELF object.
                        addElfObject(imageCache.getImageForName(name), entry.start);
                    }
                    catch (...) {
                    }
                }
            }
            if (verbose)
                *debug << "total mapped file size: " << totalSize << std::endl;
            return true; // found an NT_FILE note, so success.
        }
    }
    return false;
}
