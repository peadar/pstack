#include "libpstack/elf.h"
#ifdef WITH_ZLIB
#include "libpstack/inflatereader.h"
#endif
#ifdef WITH_LZMA
#include "libpstack/lzmareader.h"
#endif
#include "libpstack/util.h"

#include <unistd.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <limits>

std::ostream *debug = &std::clog;
int verbose = 0;

namespace Elf {

using std::string;
using std::make_shared;
using std::make_unique;

static uint32_t elf_hash(const string &text);

GlobalDebugDirectories globalDebugDirectories;
GlobalDebugDirectories::GlobalDebugDirectories() throw()
{
   add("/usr/lib/debug");
   add("/usr/lib/debug/usr"); // Add as a hack for when linker loads from /lib, but package has /usr/lib
}

void
GlobalDebugDirectories::add(const string &str)
{
   dirs.push_back(str);
}

NoteIter
Notes::begin() const
{
   return NoteIter(object, true);
}

NoteIter
Notes::end() const
{
   return NoteIter(object, false);
}

string
NoteDesc::name() const
{
   return io->readString(sizeof note);
}

Reader::csptr
NoteDesc::data() const
{
   return make_shared<OffsetReader>(io, sizeof note + roundup2(note.n_namesz, 4), note.n_descsz);
}

template <>
NamedSymbol
SymbolIterator<NamedSymbol>::operator *()
{
    return NamedSymbol(sec->symbols->readObj<Sym>(idx * sizeof(Sym)), sec->strings);
}

template <>
VersionedSymbol
SymbolIterator<VersionedSymbol>::operator *()
{
    return VersionedSymbol(sec->symbols->readObj<Sym>(idx * sizeof(Sym)), sec->strings, *sec->elf->gnu_version, idx);
}

Elf::Addr
Object::endVA() const
{
    const auto &loadable = programHeaders.at(PT_LOAD);
    const auto &last = loadable[loadable.size() - 1];
    return last.p_vaddr + last.p_memsz;
}

std::string
Object::symbolVersion(const VersionedSymbol &sym) const {
    auto vi = symbolVersions();

    int idx = sym.versionIdx & 0x7fff;
    if (idx >= 2)
        return vi->versions.at(idx);
    else
        return "";
}

static uint32_t gnu_hash(const char *s) {
    auto name = (const uint8_t *)s;
    uint32_t h = 5381;
    while (*name)
        h = (h << 5) + h + *name++;
    return h;
}

std::pair<uint32_t, Sym>
GnuHash::findSymbol(const char *name) const {
    auto symhash = gnu_hash(name);

    auto bloomword = hash->readObj<Elf::Off>(bloomoff((symhash/ELF_BITS) % header.bloom_size));

    Elf::Off mask = Elf::Off(1) << symhash % ELF_BITS |
                    Elf::Off(1) << (symhash >> header.bloom_shift) % ELF_BITS;

    if ((bloomword & mask) != mask) {
       if (verbose >= 2)
          *debug << "failed to find '" << name << "' bloom filter missed\n";
       return std::make_pair(0, Sym());
    }

    auto idx = hash->readObj<uint32_t>(bucketoff(symhash % header.nbuckets));
    if (idx < header.symoffset) {
        if (verbose >= 2)
            *debug << "failed to find '" << name << "' bad index in hash table\n";
        return std::make_pair(0, Sym());
    }
    for (;;) {
        auto sym = syms->readObj<Sym>(idx * sizeof (Sym));
        auto chainhash = hash->readObj<uint32_t>(chainoff(idx - header.symoffset));
        if ((chainhash | 1)  == (symhash | 1)) {
           if (strings->readString(sym.st_name) == name) {
              if (verbose >= 2)
                 *debug << "found '" << name << "' using GNU hash\n";
              return std::make_pair(idx, sym);
           }
        }
        if (chainhash & 1) {
           if (verbose >= 2)
               *debug << "failed to find '" << name << "' hit end of hash chain\n";
           return std::make_pair(0, Sym());
        }
        ++idx;
    }
}


GnuHash *
Object::gnu_hash()
{
    if (gnu_hash_ == nullptr) {
        auto &section { getSection( ".gnu.hash", SHT_GNU_HASH) };
        if (section) {
            auto &syms = getLinkedSection(section);
            auto &strings = getLinkedSection(syms);
            if (syms && strings)
                gnu_hash_ = make_unique<GnuHash>(section.io, syms.io, strings.io);
        }
    }
    return gnu_hash_.get();
}

SymHash *
Object::hash()
{
    if (hash_ == nullptr ) {
        auto &section {  getSection( ".hash", SHT_HASH ) };
        if (section) {
            auto &syms = getLinkedSection(section);
            auto &strings = getLinkedSection(syms);
            if (syms && strings)
                hash_.reset( new SymHash(section.io, syms.io, strings.io) );
        }
    }
    return hash_.get();
}

SymbolSection<NamedSymbol> *Object::debugSymbols() {
    return getSymtab(debugSymbols_, ".symtab", SHT_SYMTAB);
}

SymbolSection<VersionedSymbol> *Object::dynamicSymbols() {
    return getSymtab(dynamicSymbols_, ".dynsym", SHT_DYNSYM);
}

template<typename Symtype>
SymbolSection<Symtype> *
Object::getSymtab(std::unique_ptr<SymbolSection<Symtype>> &table, const char *name, int type) {
    if (table == nullptr) {
        auto &sec {getSection( name, type) };
        table.reset(new SymbolSection<Symtype>(this, sec.io, getLinkedSection(sec).io));
    }
    return table.get();
}

Object::Object(ImageCache &cache, Reader::csptr io_, bool isDebug)
    : io(std::move(io_))
    , notes(this)
    , elfHeader(io->readObj<Ehdr>(0))
    , imageCache(cache)
    , sectionHeaders(elfHeader.e_shnum)
    , debugLoaded(isDebug) // don't attempt to load separate debug info for a debug ELF.
    , lastSegmentForAddress(nullptr)
{
    /* Validate the ELF header */
    if (!IS_ELF(elfHeader) || elfHeader.e_ident[EI_VERSION] != EV_CURRENT)
        throw (Exception() << *io << ": content is not an ELF image");

    OffsetReader headers(io, elfHeader.e_phoff, elfHeader.e_phnum * sizeof (Phdr));
    for (auto hdr : ReaderArray<Phdr>(headers))
        programHeaders[hdr.p_type].push_back(hdr);
    // Sort program headers by VA.
    for (auto &phdrs : programHeaders)
        std::sort(phdrs.second.begin(), phdrs.second.end(),
                [] (const Phdr &lhs, const Phdr &rhs) {
                    return lhs.p_vaddr < rhs.p_vaddr; });

    Elf::Off off;
    int i;
    for (off = elfHeader.e_shoff, i = 0; i < elfHeader.e_shnum; i++) {
        sectionHeaders[i] = Section(io, off);
        off += elfHeader.e_shentsize;
    }

    if (elfHeader.e_shstrndx == SHN_UNDEF)
        return;

    // Create a mapping from section header names to section headers.
    auto &sshdr = sectionHeaders[elfHeader.e_shstrndx];
    size_t secid = 0;
    for (auto &h : sectionHeaders) {
        auto name = sshdr.io->readString(h.shdr.sh_name);
        namedSection[name] = secid++;
    }

    /*
     * Load dynamic entries
     */
    auto &section =  getSection(".dynamic", SHT_DYNAMIC );
    if (section) {
        ReaderArray<Dyn> content(*section.io);
        for (auto dyn : content)
           dynamic[dyn.d_tag].push_back(dyn);
    }
    gnu_version = &getSection(".gnu_version", SHT_GNU_versym);
}

const SymbolVersioning *
Object::symbolVersions() const
{
    if (symbolVersions_ != nullptr)
        return symbolVersions_.get();

    auto rv = std::make_unique<SymbolVersioning>();
    if (verbose >= 3)
       *debug << "parsing version info for " << *io << std::endl;
    auto &gnu_version_r = getSection(".gnu.version_r", SHT_GNU_verneed );
    if (gnu_version_r) {
       auto &strings = getLinkedSection(gnu_version_r);
       auto &verneednum = dynamic.at(DT_VERNEEDNUM);
       if (verneednum.size() != 0) {
          if (verbose >= 2)
             *debug << "\nhave " << verneednum[0].d_un.d_val << " version_r entries\n";

          size_t off = 0;
          for (size_t cnt = verneednum[0].d_un.d_val; cnt; --cnt) {
             auto verneed = gnu_version_r.io->readObj<Verneed>(off);
             Off auxOff = off + verneed.vn_aux;
             auto filename = strings.io->readString(verneed.vn_file);
             auto &file = rv->files[filename];
             if (verbose >= 3)
                *debug << "\treading version requirement aux entries for " << filename << std::endl;
             for (auto i = 0; i < verneed.vn_cnt; ++i) {
                auto aux = gnu_version_r.io->readObj<Vernaux>(auxOff);
                auto name = strings.io->readString(aux.vna_name);
                rv->versions[aux.vna_other] = name;
                file.push_back(aux.vna_other);
                if (verbose >= 3)
                   *debug << "\t\tfound version " << name << " for index " << aux.vna_other << std::endl;
                auxOff += aux.vna_next;
             }
             off += verneed.vn_next;
          }
       }
    }

    auto &gnu_version_d = getSection(".gnu.version_d", SHT_GNU_verdef );
    if (gnu_version_d) {
       auto &strings = getLinkedSection(gnu_version_d);
       auto &verdefnum = dynamic.at(DT_VERDEFNUM);
       if (verdefnum.size() != 0) {
          size_t off = 0;
          for (size_t cnt = verdefnum[0].d_un.d_val; cnt; --cnt) {
             auto verdef = gnu_version_d.io->readObj<Verdef>(off);
             Off auxOff = off + verdef.vd_aux;
             // There's two verdaux entries for some symbols. First is
             // "predecessor" of some sort. Last is the version string, so
             // we'll pick that one
             std::string name;
             for (auto i = 0; i < verdef.vd_cnt; ++i) {
                auto aux = gnu_version_d.io->readObj<Verdaux>(auxOff);
                name = strings.io->readString(aux.vda_name);
                auxOff += aux.vda_next;
             }
             rv->versions[verdef.vd_ndx] = name;
             if (verbose >= 3)
                *debug << "version definition " << verdef.vd_ndx << " is " << name << std::endl;
             off += verdef.vd_next;
          }
       }
    }
    symbolVersions_ = std::move(rv);
    return symbolVersions_.get();
}

const Phdr *
Object::getSegmentForAddress(Off a) const
{
    if (lastSegmentForAddress != nullptr &&
          lastSegmentForAddress->p_vaddr <= a &&
          lastSegmentForAddress->p_vaddr + lastSegmentForAddress->p_memsz > a)
       return lastSegmentForAddress;
    const auto &hdrs = getSegments(PT_LOAD);

    auto pos = std::lower_bound(hdrs.begin(), hdrs.end(), a,
            [] (const Elf::Phdr &header, Elf::Off addr) {
            return header.p_vaddr + header.p_memsz <= addr; });
    if (pos != hdrs.end() && pos->p_vaddr <= a) {
        lastSegmentForAddress = &*pos;
        return lastSegmentForAddress;
    }
    return nullptr;
}

const Object::ProgramHeaders &
Object::getSegments(Word type) const
{
    auto it = programHeaders.find(type);
    if (it == programHeaders.end()) {
        static const ProgramHeaders empty;
        return empty;
    }
    return it->second;
}

string
Object::getInterpreter() const
{
    for (auto &seg : getSegments(PT_INTERP))
        return io->readString(seg.p_offset);
    return "";
}

/*
 * Find the symbol that represents a particular address.
 */
bool
Object::findSymbolByAddress(Addr addr, int type, Sym &sym, string &name)
{
    /* Try to find symbols in these sections */
    bool haveExactZeroSizeMatch = false;

    auto findSym = [type, addr, this, &sym, &name, &haveExactZeroSizeMatch ](auto &table) {
        for (const auto &syminfo : table) {
            auto &candidate = syminfo.symbol;
            if (candidate.st_shndx >= sectionHeaders.size())
                continue;
            if (type != STT_NOTYPE && ELF_ST_TYPE(candidate.st_info) != type)
                continue;
            if (candidate.st_value > addr)
                continue;
            if (candidate.st_size + candidate.st_value <= addr) {
                if (candidate.st_size == 0 && candidate.st_value == addr) {
                    sym = candidate;
                    name = syminfo.name;
                    haveExactZeroSizeMatch = true;
                }
                continue;
            }
            auto &sec = sectionHeaders[candidate.st_shndx];
            if ((sec.shdr.sh_flags & SHF_ALLOC) == 0)
                continue;
            sym = candidate;
            name = syminfo.name;
            return true;
        }
        return false;
    };
    if (findSym(*debugSymbols()))
        return true;
    if (findSym(*dynamicSymbols()))
        return true;
    // .gnu_debugdata is a separate LZMA-compressed ELF image with just
    // a symbol table.
    if (debugData == nullptr) {
#ifdef WITH_LZMA
        auto &gnu_debugdata = getSection(".gnu_debugdata", SHT_PROGBITS );
        if (gnu_debugdata) {
           auto reader = make_shared<const LzmaReader>(gnu_debugdata.io);
           debugData = make_shared<Object>(imageCache, reader, true);
        }
#else
        static bool warned = false;
        if (!warned) {
            std::clog << "warning: no compiled support for LZMA - "
                "can't decode debug data in " << *io << "\n";
            warned = true;
        }
#endif
    }
    if (debugData && debugData->findSymbolByAddress(addr, type, sym, name))
       return true;
    return haveExactZeroSizeMatch;
}

const Section &
Object::getSection(const string &name, Word type) const
{
    auto s = namedSection.find(name);

    if (s != namedSection.end()) {
        auto &ref = sectionHeaders[s->second];
        if (ref.shdr.sh_type == type || type == SHT_NULL)
            return ref;
    }

    Object *debug = getDebug();
    if (debug)
        return debug->getSection(name, type);
    return sectionHeaders[0];
}

const Section &
Object::getSection(Word idx) const
{
    if (sectionHeaders[idx].shdr.sh_type != SHT_NULL)
        return sectionHeaders[idx];
    auto debug = getDebug();
    if (debug)
        return debug->getSection(idx);
    return sectionHeaders[0];
}

const Section &
Object::getLinkedSection(const Section &from) const
{
    if (!from)
        return from;
    if (&from >= &sectionHeaders[0] && &from <= &sectionHeaders[sectionHeaders.size() - 1])
        return sectionHeaders[from.shdr.sh_link];
    auto debug = getDebug();
    if (debug)
       return debug->getLinkedSection(from);
    return sectionHeaders[0];
}

/*
 * Locate a named symbol in an ELF image - this uses the dynamic symbol table
 * which provides hash-accellerated access. (via either .hash or .gnu_hash
 * section)
 */
VersionedSymbol
Object::findDynamicSymbol(const std::string &name)
{
    Sym sym;
    uint32_t idx;

    std::tie(idx, sym) = gnu_hash() ? gnu_hash()->findSymbol(name)
             : hash() ? hash()->findSymbol(name)
             : std::make_pair(uint32_t(0), Sym());

    if (idx == 0)
        return VersionedSymbol();

    // We found a symbol in our hash table. Find its version if we can.
    return VersionedSymbol(sym, name, *gnu_version, idx);
}

// XXX: if we're doing name lookups on symbols, consider caching them all in a
// hash table, rather than doing linear scans for each symbol we haven't
// looked-up yet.
NamedSymbol
Object::findDebugSymbol(const string &name)
{
    auto &syment = cachedSymbols[name];
    if (syment.disposition == CachedSymbol::SYM_NEW) {
        auto found = debugSymbols()->linearSearch(name, syment.sym);
        syment.disposition = found ? CachedSymbol::SYM_FOUND : CachedSymbol::SYM_NOTFOUND;
    }
    return syment.disposition == CachedSymbol::SYM_FOUND ? NamedSymbol(syment.sym, name) : NamedSymbol();
}

Object::~Object() = default;

Object *
Object::getDebug() const
{
    if (debugLoaded)
        return debugObject.get();
    debugLoaded = true;

    // Use the build ID to find debug data.
    for (const auto &note : notes) {
        if (note.name() == "GNU" && note.type() == GNU_BUILD_ID) {
            std::ostringstream dir;
            dir << ".build-id/";
            size_t i;
            auto io = note.data();
            std::vector<unsigned char> data(io->size());
            io->readObj(0, &data[0], io->size());
            dir << std::hex << std::setw(2) << std::setfill('0') << int(data[0]);
            dir << "/";
            for (i = 1; i < size_t(io->size()); ++i)
                dir << std::setw(2) << int(data[i]);
            dir << ".debug" << std::dec;
            debugObject = imageCache.getDebugImage(dir.str());
            break;
        }
    }

    // If that doesn't work, maybe the gnu_debuglink is valid?
    if (!debugObject) {
        // if we have a debug link, use that to attempt to find the debug file.
        auto &hdr = getSection(".gnu_debuglink", SHT_PROGBITS);
        if (hdr) {
            auto link = hdr.io->readString(0);
            auto dir = dirname(stringify(*io));
            debugObject = imageCache.getDebugImage(dir + "/" + link); //
        }
    }

    if (!debugObject) {
        if (verbose >= 2)
           *debug << "no debug object for " << *this->io << "\n";
        return nullptr;
    }

    if (verbose >= 2)
        *debug << "found debug object " << *debugObject->io << " for " << *io << "\n";

    // Validate that the .dynamic section in the debug object and the one in
    // the original image have the same .sh_addr.
    auto &s = getSection(".dynamic", SHT_NULL);
    auto &d = debugObject->getSection(".dynamic", SHT_NULL);

    if (d.shdr.sh_addr != s.shdr.sh_addr) {
        Elf::Addr diff = s.shdr.sh_addr - d.shdr.sh_addr;
        IOFlagSave _(std::clog);
        std::clog << "warning: dynamic section for debug symbols "
           << *debugObject->io << " loaded for object "
           << *this->io << " at different offset: diff is "
           << std::hex << diff
           << ", assuming " << *this->io << " is prelinked" << std::dec << std::endl;

        // looks like the exe has been prelinked - adjust the debug info too.
        for (auto &sect : debugObject->sectionHeaders)
            sect.shdr.sh_addr += diff;

        for (auto &sectType : debugObject->programHeaders)
            for (auto &sect : sectType.second)
                sect.p_vaddr += diff;
    }
    return debugObject.get();
}

template <typename Symtype> bool
SymbolSection<Symtype>::linearSearch(const string &name, Sym &sym) const
{
    for (const auto &info : *this) {
        if (name == info.name) {
            sym = info.symbol;
            return true;
        }
    }
    return false;
}

SymHash::SymHash(Reader::csptr hash_,
      Reader::csptr syms_, Reader::csptr strings_)
    : hash(std::move(hash_))
    , syms(std::move(syms_))
    , strings(std::move(strings_))
{
    // read the hash table into local memory.
    size_t words = hash->size() / sizeof (Word);
    data.resize(words);
    hash->readObj(0, &data[0], words);
    nbucket = data[0];
    nchain = data[1];
    buckets = &data[0] + 2;
    chains = buckets + nbucket;
}

std::pair<uint32_t, Sym>
SymHash::findSymbol(const string &name)
{
    uint32_t bucket = elf_hash(name) % nbucket;
    for (Word i = buckets[bucket]; i != STN_UNDEF; i = chains[i]) {
        auto candidate = syms->readObj<Sym>(i * sizeof (Sym));
        auto candidateName = strings->readString(candidate.st_name);
        if (candidateName == name)
            return std::make_pair(i, candidate);
    }
    return std::make_pair(0, Sym());
}

/*
 * Culled from System V Application Binary Interface
 */
static uint32_t
elf_hash(const string &text)
{
    uint32_t h = 0, g;
    for (auto c : text) {
        h = (h << 4) + c;
        if ((g = h & 0xf0000000) != 0)
            h ^= g >> 24;
        h &= ~g;
    }
    return (h);
}

Section::Section(const Reader::csptr &image, Off off)
{
    image->readObj(off, &shdr);
    // Null sections get null readers.
    if (shdr.sh_type == SHT_NULL) {
        io = make_shared<NullReader>();
        return;
    }
    auto rawIo = make_shared<OffsetReader>(image, shdr.sh_offset, shdr.sh_size);
    if ((shdr.sh_flags & SHF_COMPRESSED) == 0) {
        io = rawIo;
    } else {
#ifdef WITH_ZLIB
        auto chdr = rawIo->readObj<Chdr>(0);
        io = make_shared<InflateReader>(chdr.ch_size, OffsetReader(rawIo,
                 sizeof chdr, shdr.sh_size - sizeof chdr));
#else
        static bool warned = false;
        if (!warned) {
            warned = true;
            std::clog <<"warning: no support configured for compressed debug info in "
               << *image << std::endl;
        }
        io = make_shared<NullReader>();
#endif
    }
}

Object::sptr
ImageCache::getImageForName(const string &name, bool isDebug) {
    auto res = getImageIfLoaded(name);
    if (res != nullptr) {
        return res;
    }
    auto item = make_shared<Object>(*this, std::make_shared<MmapReader>(name), isDebug);
    // don't cache negative entries: assign into the cache after we've constructed:
    // a failure to load the image will throw.
    cache[name] = item;
    return item;
}

ImageCache::ImageCache() : elfHits(0), elfLookups(0) {}
ImageCache::~ImageCache() {
    if (verbose >= 2) {
        *debug << "ELF image cache: lookups: " << elfLookups << ", hits=" << elfHits << std::endl;
        for (const auto &items : cache) {
            assert(items.second);
            *debug << "\t" << *items.second->io << std::endl;
        }
    }
}

Object::sptr
ImageCache::getImageIfLoaded(const string &name)
{
    elfLookups++;
    auto it = cache.find(name);
    if (it != cache.end()) {
        elfHits++;
        return it->second;
    }
    return Object::sptr();
}

Object::sptr
ImageCache::getDebugImage(const string &name) {
    // XXX: verify checksum.
    for (const auto &dir : globalDebugDirectories.dirs) {
        auto img = getImageIfLoaded(stringify(dir, "/", name));
        if (img)
            return img;
    }
    for (const auto &dir : globalDebugDirectories.dirs) {
        try {
           return getImageForName(stringify(dir, "/", name), true);
        }
        catch (const std::exception &ex) {
            continue;
        }
    }
    return Object::sptr();
}

void
ImageCache::flush(Object::sptr o)
{
   for (auto it = cache.begin(); it != cache.end(); ++it) {
      if (it->second == o) {
         cache.erase(it);
         return;
      }
   }
}

VersionedSymbol::VersionedSymbol(const Sym &sym_, const std::string &name_, const Section &versionInfo, size_t idx)
    : NamedSymbol(sym_, name_)
    , versionIdx(versionInfo ? versionInfo.io->readObj<Half>(idx * sizeof (Half)) : -1)
{ }

}
