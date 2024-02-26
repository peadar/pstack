#include "libpstack/dwarf.h"
#include "libpstack/global.h"
#include "libpstack/elf.h"
#include "libpstack/proc.h"

#include <cassert>

#include <iostream>

namespace pstack::Procman {
CoreProcess::CoreProcess(Elf::Object::sptr exec, Elf::Object::sptr core,
        const PstackOptions &options, Dwarf::ImageCache &imageCache)
    : Process(std::move(exec), std::make_shared<CoreReader>(this, core), options, imageCache)
    , coreImage(std::move(core))
{

#ifdef NT_PRSTATUS
    for (auto note : coreImage->notes()) {
        if (note.name() == "CORE" && note.type() == NT_PRSTATUS) {
            tasks.push_back( note.data()->readObj<prstatus_t>(0) );
            prstatus_t &task = tasks.back();
            if (verbose)
               *debug << "task " << task.pr_pid << " current sig is " << task.pr_cursig << "\n";
        }
#endif
    }
}

void CoreProcess::listLWPs(std::function<void(lwpid_t)> cb) {
   for (auto &task : tasks)
      cb(task.pr_pid);
}

Reader::csptr
CoreProcess::getAUXV() const
{
#ifdef __linux__
    for (auto note : coreImage->notes()) {
       if (note.name() == "CORE" && note.type() == NT_AUXV) {
           return note.data();
           break;
       }
    }
#endif
    return {};
}

void CoreReader::describe(std::ostream &os) const
{
    if (core)
        os << *core->io;
    else
        os << "no backing core file";
}

static size_t
readFromHdr(const Elf::Object &obj, const Elf::Phdr *hdr, Elf::Off addr,
            char *ptr, Elf::Off size, Elf::Off *toClear)
{
    Elf::Off rv;
    Elf::Off off = addr - hdr->p_vaddr; // offset in header of our ptr.
    if (off < hdr->p_filesz) {
        // some of the data is in the file: read min of what we need and that.
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
CoreReader::read(Off remoteAddr, size_t size, char *ptr) const
{
    Elf::Off start = remoteAddr;
    while (size != 0) {

        Elf::Off zeroes = 0;
        if (core) {
           // Locate "remoteAddr" in the core file
           const Elf::Phdr * hdr = core->getSegmentForAddress(remoteAddr);
           if (hdr != nullptr) {
               // The start address appears in the core (or is defaulted from it)
               size_t rc = readFromHdr(*core, hdr, remoteAddr, ptr, size, &zeroes);
               remoteAddr += rc;
               ptr += rc;
               size -= rc;
               if (rc != 0 && zeroes == 0)
                   // we got some data from the header, and there's nothing to default
                   continue;
           }
        }
        // Either no data in core, or it was incomplete to this point: search loaded objects.
        Elf::Off loadAddr;
        const Elf::Phdr *hdr;
        Elf::Object::sptr obj;
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

CoreReader::CoreReader(Process *p_, Elf::Object::sptr core_) : p(p_), core(core_) { }

bool
CoreProcess::getRegs(lwpid_t pid, Elf::CoreRegisters *reg)
{
#ifdef NT_PRSTATUS
   for (auto &task : tasks) {
        static_assert(sizeof task.pr_reg == sizeof *reg);
        if (task.pr_pid == pid) {
            memcpy(reg, &task.pr_reg, sizeof(*reg));
            return true;
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
}

pid_t
CoreProcess::getPID() const
{
    return tasks.size() != 0 ? tasks[0].pr_pid : -1;
}

FileEntries::iterator::iterator(const FileEntries &entries, ReaderArray<FileEntry>::iterator pos)
        : entries(entries)
        , entriesIterator(pos) {
    fetch();
}

struct NamedEntry {
    std::pair<std::string, FileEntry> content;
    int operator < (const NamedEntry &rhs) const {
        return content.second.start < rhs.content.second.start;
    }
};

void
FileEntries::iterator::fetch() {
    cur = std::make_pair(entries.names->readString(nameoff), *entriesIterator);
}

FileEntries::iterator &FileEntries::iterator::operator++() {
    ++entriesIterator;
    nameoff += cur.first.size() + 1;
    fetch();
    return *this;
}

std::vector<AddressRange>
CoreProcess::addressSpace() const {
    // First, go through the NT_FILE note if we have one - that gives us filenames
    std::map<Elf::Off, std::pair<std::string, FileEntry>> entries;
    for (auto entry : FileEntries(*coreImage))
        entries[entry.second.start] = entry;

    // Now go through the PT_LOAD segments in the core to generate the result.
    std::vector<AddressRange> rv;
    for (const auto &hdr : coreImage->getSegments(PT_LOAD)) {
        auto ub = entries.upper_bound(hdr.p_vaddr);
        std::string name;
        if (ub != entries.begin()) {
            --ub;
            if (ub->first >= hdr.p_vaddr && ub->second.second.end <= hdr.p_vaddr + hdr.p_memsz)
                name = ub->second.first;
        }
        rv.push_back({hdr.p_vaddr, hdr.p_vaddr + hdr.p_memsz, hdr.p_vaddr + hdr.p_filesz, 0, {0, 0, 0, name}, {}});
    }
    return rv;
}

bool
CoreProcess::loadSharedObjectsFromFileNote()
{
    // If the core is truncated, and we have no access to the link map, we make
    // a guess at what shared libraries are mapped by looking in the NT_FILE
    // note if present.
    unsigned long totalSize = 0;
    for (auto [name, entry] : FileEntries(*coreImage)) {
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

std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::FileEntry> &j) {
    return JObject(os)
        .field("start", j.object.start)
        .field("end", j.object.end)
        .field("fileOff", j.object.fileOff);
}
