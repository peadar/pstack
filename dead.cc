#include "libpstack/dwarf.h"
#include "libpstack/elf.h"
#include "libpstack/proc.h"

#include <iostream>

namespace pstack::Procman {

CoreProcess::CoreProcess(Context &ctx, Elf::Object::sptr exec, Elf::Object::sptr core)
   : Process(ctx, std::move(exec), std::make_shared<CoreReader>(this, core))
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

// returns the amount of data read, and the amount of data that is covered by the phdr, but not present.
std::pair< size_t, size_t >
readFromSegment(const Reader::csptr &io, const Elf::Phdr *hdr, Elf::Off addr, char *ptr, Elf::Off size) {
    Elf::Off rv;
    Elf::Off off = addr - hdr->p_vaddr; // offset in header of our ptr.
    if (off < hdr->p_filesz) {
        // some of the data is in the file: read min of what we need and that.
        Elf::Off fileSize = std::min(hdr->p_filesz - off, size);
        rv = io->read(hdr->p_offset + off, fileSize, ptr);
        if (rv != fileSize)
            throw (Exception() << "unexpected short read in core file");
        off += rv;
        size -= rv;
    } else {
        rv = 0;
    }

    // How much space is covered by the segment, but not present in the file?
    Elf::Off missing = hdr->p_memsz > hdr->p_filesz ? hdr->p_memsz - hdr->p_filesz : 0;
    return { rv, std::min( size, missing ) };
}

size_t
CoreReader::read(Off remoteAddr, size_t size, char *ptr) const
{
    const Elf::Off start = remoteAddr;
    const Elf::Off end = remoteAddr + size;
    char *const ptrStart = ptr;
    char *const ptrEnd = ptr + size;
    
    auto loadSegs = getSegments(PT_LOAD);
    auto coreSeg = std::lower_bound( loadSegs.begin(), loadSegs.end(), remoteAddr, [](const Elf::Phdr &header, Elf::Off addr) { return header.p_vaddr + header.p_memsz <= addr; } );


    // This gets a bit complicated
    //
    // Data can come from the core, or from a loaded library. (for now, we
    // don't do other mappings) We can also zero-fill if there's a segment
    // where memsz > filesz.
    //
    // Data in the core takes precedence over data from mapped objects. Actual
    // data in either takes precedence over zero-filling.


    while (ptr != ptrEnd) {
        // If the current phdr covers the address, copy data out of it.
        if (coreSeg != loadSegs.end()
                && coreSeg->p_vaddr <= remoteAddr
                && coreSeg->p_vaddr + coreSeg->p_memsiz >= remoteAddr) {
            
            auto segmentOff = remoteAddr - hdr->p_vaddr;
            auto readCount = std::min(hdr->p_filesz - segmentOff, ptrEnd-ptr);
            auto actuallyRead = core->read(hdr->p_offset + segmentOff, readCount, ptr);

            ptr += actuallyRead;
            remoteAddr += actuallyRead;

            if (actuallyRead != readCount) {
                return ptr - ptrStart;
            }
        }
        // Read everything we can up to the *next* core segment from any file mappings
        auto nextSeg = coreSeg;

        Elf::Addr nextCoreAddr; // next address in the core we can use.
        if (nextSeg != loadSegs.end()) {
            ++nextSeg;
            nextCoreAddr = nextSeg->p_vaddr;
        } else {
            nextCoreAddr = end;
        }

        while (remoteAddr < nextCoreAddr) {
            // until we get to the next relevant core segment that has data in
            // the file itsel, pull data from mapped files.
            auto [loadAddr, obj, hdr] = p->findSegment(remoteAddr);
            if (hdr != nullptr) {
                // header in an object - try reading from here.
                auto hdroff = remoteAddr - loadAddr - hdr->p_vaddr;
                auto sz = hdr->p_filesz - hdroff;
                auto sz = std::min( sz, nextCoreAddr - remoteAddr );
                auto count = obj->io->read( hdr->p_offset + hdroff, sz, ptr );
                remoteAddr += count;
                ptr += count;
                if (count != sz) {
                    return ptr - ptrStart;
                }

                if (hdr->p_memsz > hdr->p_filesz) {
                    auto zerofill = hdr->p_memsz - hdr->p_filesz;
                    zerofill = std::min(zerofill, nextCoreAddr - remoteAddr);
                    if (zerofill) {
                        memset(ptr, 0, zerofill);
                        ptr += zerofill;
                        remoteAddr += zerofill;
                    }
                }
            }
        }



        // find the first segment covering an address at or after remoteAddr 




        size_t rc, unread = size;
        if (core) {
           // Locate "remoteAddr" in the core file
           const Elf::Phdr * hdr = core->getSegmentForAddress(remoteAddr);
           if (hdr != nullptr) {
               // The start address appears in the core (or is defaulted from it)
               std::tie( rc, unread ) = readFromSegment(core->io, hdr, remoteAddr, ptr, size );
               remoteAddr += rc;
               ptr += rc;
               size -= rc;
           }
        }

        if (unread) {
            // There's a chunk of data up to "unread" that has 

            if (unread > rc) {
                unread -= rc;
                memset(ptr, 0, unread);
                size -= unread;
                remoteAddr += unread;
                ptr += unread;
            }
        }

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
}

struct NamedEntry {
    std::pair<std::string, FileEntry> content;
    bool operator < (const NamedEntry &rhs) const {
        return content.second.start < rhs.content.second.start;
    }
};

void
FileEntries::iterator::fetch() {
   if (!fetched && entries.names) {
       cur = std::make_pair(entries.names->readString(nameoff), *entriesIterator);
       fetched = true;
   }
}

FileEntries::iterator &FileEntries::iterator::operator++() {
    fetch();
    ++entriesIterator;
    nameoff += cur.first.size() + 1;
    fetched = false;
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
        std::set<AddressRange::Permission> flags;
        if ((hdr.p_flags & PF_W) != 0)
           flags.insert(AddressRange::Permission::write);
        if ((hdr.p_flags & PF_R) != 0)
           flags.insert(AddressRange::Permission::read);
        if ((hdr.p_flags & PF_X) != 0)
           flags.insert(AddressRange::Permission::exec);
        rv.push_back( { hdr.p_vaddr, hdr.p_vaddr + hdr.p_memsz,
                hdr.p_vaddr + hdr.p_filesz, 0, {0, 0, 0, name}, flags, {}});
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
        if (context.verbose > 2)
            *context.debug << "NT_FILE mapping " << name << " "
                << (void *)entry.start << " " << size << "\n";
        if (entry.fileOff == 0) {
            try {
                // Just try and load it like an ELF object.
                addElfObject(name, nullptr, entry.start);
            }
            catch (const std::exception &ex) {
               *context.debug << "failed to add ELF object " << name << ": " << ex.what() << "\n";
            }
        }
    }
    if (context.verbose > 0)
        *context.debug << "total mapped file size: " << totalSize << "\n";
    return true; // found an NT_FILE note, so success.
}

std::optional<siginfo_t>
CoreProcess::getSignalInfo() const {
   for ( const auto &note : coreImage->notes() ) {
      if ( note.name() == "CORE" && note.type() == NT_SIGINFO ) {
         return note.data()->readObj<siginfo_t>(0);
      }
   }
   return std::nullopt;
}

std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::FileEntry> &j) {
    return JObject(os)
        .field("start", j.object.start)
        .field("end", j.object.end)
        .field("fileOff", j.object.fileOff);
}
}

