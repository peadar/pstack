#include "libpstack/dwarf.h"
#include "libpstack/global.h"
#include "libpstack/elf.h"
#include "libpstack/proc.h"

#include <iostream>

namespace pstack::Procman {

CoreProcess::CoreProcess(Elf::Object::sptr exec, Elf::Object::sptr core,
      const PstackOptions &options, Dwarf::ImageCache &imageCache)
   : Process(std::move(exec), std::make_shared<CoreReader>(this, core), options, imageCache)
     , prpsinfo{}
     , coreImage(std::move(core))
{
   for (auto note : coreImage->notes()) {
      if (note.name() == "CORE") {
         switch  (note.type() ) {
            case NT_PRSTATUS: {
               // for NT_PRSTATUS notes, mark the index of the current note in our
               // vector as the start of the notes for that LWP. When looking
               // for an LWP-related note, we start at the index for that LWPs
               // NT_PRSTATUS, and consider it a failure if we reach another
               // NT_PRSTATUS or the end of the list.
               auto task = note.data()->readObj<prstatus_t>(0);
               lwpToPrStatusIdx[task.pr_pid] = notes.size();
               break;
            }
            case NT_PRPSINFO: {
               note.data()->readObj(0, &prpsinfo); // hold on to a copy of this
               break;
            }
            default:
               break;
         }
      }
      notes.push_back( note );
   }
}

void CoreProcess::listLWPs(std::function<void(lwpid_t)> cb) {
   for (auto &task : lwpToPrStatusIdx)
      cb(task.first);
}

Reader::csptr
CoreProcess::getAUXV() const
{
#ifdef __linux__
    for (const auto &note : notes) {
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

size_t
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
        auto [loadAddr, obj, hdr] = p->findSegment(remoteAddr);
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

CoreReader::CoreReader(Process *p_, Elf::Object::sptr core_) : p(p_), core(std::move( core_ ) ) { }

size_t
CoreProcess::getRegs(lwpid_t lwpid, int code, size_t size, void *data)
{
   auto idx = lwpToPrStatusIdx.find( lwpid );
   if ( idx == lwpToPrStatusIdx.end() ) {
      return 0;
   }
   for (size_t i = idx->second;;) {
      if (notes[i].type() == code) {
         if (code == NT_PRSTATUS) {
            auto prstatus = notes[i].data()->readObj<prstatus_t>(0);
            size = std::min(size, sizeof prstatus.pr_reg);
            memcpy(data, &prstatus.pr_reg, size);
         } else {
            size = std::min(size, size_t(notes[i].data()->size()));
            notes[i].data()->read(0, size, reinterpret_cast<char *>(data));
         }
         return size;
      }
      ++i;
      if (i == notes.size() || ( notes[i].type() == NT_PRSTATUS && notes[i].name() == "CORE") ) {
         // We're done if that's all the notes, or the next note is the start of a new LWP.
         break;
      }
   }
   return 0;
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
    return prpsinfo.pr_pid;
}

FileEntries::iterator::iterator(const FileEntries &entries, ReaderArray<FileEntry>::iterator pos)
        : entries(entries)
        , entriesIterator(pos) {
    fetch();
}

struct NamedEntry {
    std::pair<std::string, FileEntry> content;
    bool operator < (const NamedEntry &rhs) const {
        return content.second.start < rhs.content.second.start;
    }
};

void
FileEntries::iterator::fetch() {
   if (entries.names)
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
        std::set<AddressRange::Flags> flags;
        if ((hdr.p_flags & PF_W) != 0)
           flags.insert(AddressRange::Flags::write);
        if ((hdr.p_flags & PF_R) != 0)
           flags.insert(AddressRange::Flags::read);
        if ((hdr.p_flags & PF_X) != 0)
           flags.insert(AddressRange::Flags::exec);
        rv.push_back( { hdr.p_vaddr, hdr.p_vaddr + hdr.p_memsz,
                hdr.p_vaddr + hdr.p_filesz, 0, {0, 0, 0, name}, {}});
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
            *debug << "NT_FILE mapping " << name << " "
                << (void *)entry.start << " " << size << "\n";
        if (entry.fileOff == 0) {
            try {
                // Just try and load it like an ELF object.
                addElfObject(name, nullptr, entry.start);
            }
            catch (const std::exception &ex) {
               *debug << "failed to add ELF object " << name << ": " << ex.what() << "\n";
            }
        }
    }
    if (verbose > 0)
        *debug << "total mapped file size: " << totalSize << "\n";
    return true; // found an NT_FILE note, so success.
}

}

std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::FileEntry> &j) {
    return JObject(os)
        .field("start", j.object.start)
        .field("end", j.object.end)
        .field("fileOff", j.object.fileOff);
}
