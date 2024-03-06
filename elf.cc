#include "libpstack/elf.h"
#include "libpstack/global.h"
#include "libpstack/stringify.h"
#include "libpstack/ioflag.h"
#include "libpstack/fs.h"
#ifdef WITH_ZLIB
#include "libpstack/inflatereader.h"
#endif
#ifdef WITH_LZMA
#include "libpstack/lzmareader.h"
#endif

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <cstring>

#include <unistd.h>

namespace pstack::Elf {

using std::string;
using std::make_shared;

static uint32_t elf_hash(const string &text);

bool noExtDebug;

std::vector<string> globalDebugDirectories;

namespace {
bool setupGDD()
{
   // Add as a hack for when linker loads from /lib, but package has /usr/lib
   globalDebugDirectories.push_back("/usr/lib/debug");
   globalDebugDirectories.push_back("/usr/lib/debug/usr");
   return false;
}
bool _gdd_init = setupGDD();
}

Notes::iterator
Notes::begin() const
{
   return iterator(object, true);
}

Notes::iterator
Notes::end() const
{
   return iterator(object, false);
}

Notes::iterator::iterator(const Object *object_, bool begin)
    : object(object_)
    , phdrs(object_->getSegments(PT_NOTE))
    , offset(0)
{
    phdrsi = begin ? phdrs.begin() : phdrs.end();
    if (phdrsi != phdrs.end()) {
        startSection();
        readNote();
    }
}

void Notes::iterator::startSection() {
    offset = 0;
    io = object->io->view("note section", Off(phdrsi->p_offset), size_t(phdrsi->p_filesz));
}

Notes::iterator &Notes::iterator::operator++()
{
    auto newOff = offset;
    newOff += sizeof curNote + curNote.n_namesz;
    newOff = roundup2(newOff, 4);
    newOff += curNote.n_descsz;
    newOff = roundup2(newOff, 4);
    if (newOff >= phdrsi->p_filesz) {
        if (++phdrsi == phdrs.end()) {
            offset = 0;
            return *this;
        }
        startSection();
    } else {
        offset = newOff;
    }
    readNote();
    return *this;
}

string
NoteDesc::name() const
{
   return io->readString(sizeof note);
}

Reader::csptr
NoteDesc::data() const
{
   return io->view("note descriptor", sizeof note + roundup2(note.n_namesz, 4), note.n_descsz);
}

Elf::Addr
Object::endVA() const
{
    const auto &loadable = programHeaders.at(PT_LOAD);
    const auto &last = loadable[loadable.size() - 1];
    return last.p_vaddr + last.p_memsz;
}

std::optional<std::string>
Object::symbolVersion(VersionIdx idx) const {
    auto vi = symbolVersions();

    int i = idx.idx & 0x7fff;
    if (i >= 2)
        return vi->versions.at(i);
    else
        return std::nullopt;
}

VersionIdx Object::versionIdxForSymbol(size_t idx) const {
   return VersionIdx(*gnu_version ? gnu_version->io()->readObj<Half>(idx * 2) : -1);
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
       return std::make_pair(0, undef());
    }

    auto idx = hash->readObj<uint32_t>(bucketoff(symhash % header.nbuckets));
    if (idx < header.symoffset) {
        if (verbose >= 2)
            *debug << "failed to find '" << name << "' bad index in hash table\n";
        return std::make_pair(0, undef());
    }
    for (;;) {
        auto sym = syms->readObj<Sym>(idx * sizeof (Sym));
        auto chainhash = hash->readObj<uint32_t>(chainoff(idx - header.symoffset));
        if ((chainhash | 1)  == (symhash | 1) && strings->readString(sym.st_name) == name)
              return std::make_pair(idx, sym);
        if (chainhash & 1) {
           if (verbose >= 2)
               *debug << "failed to find '" << name << "' hit end of hash chain\n";
           return std::make_pair(0, undef());
        }
        ++idx;
    }
}

SymbolSection *Object::debugSymbols() {
    return getSymtab(debugSymbols_, ".symtab", SHT_SYMTAB);
}

SymbolSection *Object::dynamicSymbols() {
    return getSymtab(dynamicSymbols_, ".dynsym", SHT_DYNSYM);
}

SymbolSection *
Object::getSymtab(std::unique_ptr<SymbolSection> &table, const char *name, int type) {
    if (table == nullptr) {
        auto &sec {getDebugSection( name, type ) };
        table.reset(new SymbolSection(this, sec.io(), getLinkedSection(sec).io()));
    }
    return table.get();
}

Object::Object(ImageCache &cache, Reader::csptr io_, bool isDebug)
    : io(std::move(io_))
    , elfHeader(io->readObj<Ehdr>(0))
    , imageCache(cache)
    , debugLoaded(isDebug) // don't attempt to load separate debug info for a debug ELF.
    , lastSegmentForAddress(nullptr)
{
    /* Validate the ELF header */
    if (!IS_ELF(elfHeader) || elfHeader.e_ident[EI_VERSION] != EV_CURRENT)
        throw (Exception() << *io << ": content is not an ELF image");

    auto headers = io->view("program headers", elfHeader.e_phoff, elfHeader.e_phnum * sizeof (Phdr));
    for (auto hdr : ReaderArray<Phdr>(*headers))
        programHeaders[hdr.p_type].push_back(hdr);
    // Sort program headers by VA.
    for (auto &phdrs : programHeaders)
        std::sort(phdrs.second.begin(), phdrs.second.end(),
                [] (const Phdr &lhs, const Phdr &rhs) {
                    return lhs.p_vaddr < rhs.p_vaddr; });

    Elf::Off off;
    int i;

    // Make sure the header sections are present in the reader, otherwise, skip.
    if (elfHeader.e_shoff < io->size()) {
       // If there are too many headers, we need to look in the first section header
       // to get the actual count.
       //
       int headerCount;
       if (elfHeader.e_shnum == 0 && elfHeader.e_shentsize != 0) {
          headerCount = 1;
       } else {
          headerCount = elfHeader.e_shnum;
          sectionHeaders.reserve(headerCount);
       }

       for (off = elfHeader.e_shoff, i = 0; i < headerCount; i++) {
           sectionHeaders.emplace_back(std::make_unique<Section>(this, off));
           if (i == 0 && elfHeader.e_shnum == 0) {
               headerCount = sectionHeaders[0]->shdr.sh_size;
               sectionHeaders.reserve(headerCount);
           }
           off += elfHeader.e_shentsize;
       }
       if (sectionHeaders.size() == 0) {
           sectionHeaders.push_back(std::make_unique<Section>());
       }

       if (elfHeader.e_shstrndx != SHN_UNDEF) {
          // Create a mapping from section header names to section headers.
          // We need to do this after reading all the section headers, because
          // until then we don't have the details of the shstr section
          //
          // We need to deal with the fact that e_shstrndx might be too small
          // to hold the index of the string section, and look in sh_link if so.
          int shstrSec = elfHeader.e_shstrndx == SHN_XINDEX ?
              sectionHeaders[0]->shdr.sh_link :
              elfHeader.e_shstrndx;
          auto &sshdr = sectionHeaders[shstrSec];
          size_t secid = 0;
          for (auto &h : sectionHeaders) {
              auto name = sshdr->io()->readString(h->shdr.sh_name);
              namedSection[name] = secid++;
              h->name = name;
          }

          /*
           * Load dynamic entries
           */
          auto &section = getSection(".dynamic", SHT_DYNAMIC );
          if (section) {
              ReaderArray<Dyn> content(*section.io());
              for (auto dyn : content)
                 dynamic[dyn.d_tag].push_back(dyn);
          }
          gnu_version = &getSection(".gnu.version", SHT_GNU_versym);
       }
    } else {
        // leave a null section no matter what.
        sectionHeaders.push_back(std::make_unique<Section>());
    }
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
             auto verneed = gnu_version_r.io()->readObj<Verneed>(off);
             Off auxOff = off + verneed.vn_aux;
             auto filename = strings.io()->readString(verneed.vn_file);
             auto &file = rv->files[filename];
             if (verbose >= 3)
                *debug << "\treading version requirement aux entries for " << filename << std::endl;
             for (auto i = 0; i < verneed.vn_cnt; ++i) {
                auto aux = gnu_version_r.io()->readObj<Vernaux>(auxOff);
                auto name = strings.io()->readString(aux.vna_name);
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
             auto verdef = gnu_version_d.io()->readObj<Verdef>(off);
             Off auxOff = off + verdef.vd_aux;
             // There's two verdaux entries for some symbols. First is
             // "predecessor" of some sort. Last is the version string, so
             // we'll pick that one
             std::string name;
             for (auto i = 0; i < verdef.vd_cnt; ++i) {
                auto aux = gnu_version_d.io()->readObj<Verdaux>(auxOff);
                name = strings.io()->readString(aux.vda_name);
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

const std::map<Elf::Word, Object::ProgramHeaders> &
Object::getAllSegments() const {
    return programHeaders;
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
std::optional<std::pair<Sym, string>>
Object::findSymbolByAddress(Addr addr, int type)
{
    /* Try to find symbols in these sections */
    bool haveExactZeroSizeMatch = false;

    Sym sym;
    std::string name;
    auto findSym = [&] (auto &table) {
        for (const auto &candidate : table) {
            if (candidate.st_shndx >= sectionHeaders.size())
                continue;
            if (type != STT_NOTYPE && ELF_ST_TYPE(candidate.st_info) != type)
                continue;
            if (candidate.st_value > addr)
                continue;
            if (candidate.st_size + candidate.st_value <= addr) {
                if (candidate.st_size == 0 && candidate.st_value == addr) {
                    sym = candidate;
                    name = table.name(candidate);
                    haveExactZeroSizeMatch = true;
                }
                continue;
            }
            auto &sec = sectionHeaders[candidate.st_shndx];
            if ((sec->shdr.sh_flags & SHF_ALLOC) == 0)
                continue;
            sym = candidate;
            name = table.name(candidate);
            return true;
        }
        sym.st_shndx = SHN_UNDEF;
        return false;
    };
    if (findSym(*debugSymbols()))
        return std::make_pair( sym, name );
    if (findSym(*dynamicSymbols()))
        return std::make_pair( sym, name );
    // .gnu_debugdata is a separate LZMA-compressed ELF image with just
    // a symbol table.
    if (debugData == nullptr) {
#ifdef WITH_LZMA
        auto &gnu_debugdata = getSection(".gnu_debugdata", SHT_PROGBITS );
        if (gnu_debugdata) {
           auto reader = make_shared<const LzmaReader>(gnu_debugdata.io());
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
    if (debugData) {
        auto debugSym = debugData->findSymbolByAddress(addr, type);
        if (debugSym)
            return debugSym;
    }

    if (haveExactZeroSizeMatch)
        return std::make_pair( sym, name );
    sym.st_shndx = SHN_UNDEF;
    return std::nullopt;
}

const Section &
Object::getSection(const string &name, Word type) const
{
    auto s = namedSection.find(name);
    if (s != namedSection.end()) {
        auto &ref = sectionHeaders[s->second];
        if (ref->shdr.sh_type == type || type == SHT_NULL)
            return *ref;
    }
    if (name.rfind(".debug_", 0) == 0) {
        // We check for the section names in Section::io() to do decompression
        // for this type of section.
        const auto &compressed = getSection(std::string(".z") + name.substr(1), type);
        if (compressed)
            return compressed;
    }
    static std::string dwosuffix = ".dwo";
    if (!std::equal(dwosuffix.rbegin(), dwosuffix.rend(), name.rbegin()))
       return getSection(name + ".dwo", type);
    return *sectionHeaders[0];
}

const Section &
Object::getDebugSection(const string &name, Word type) const
{
    auto &local = getSection(name, type);
    if (local && local.shdr.sh_type != SHT_NOBITS)
        return local;
    auto debug = getDebug();
    if (debug)
        return debug->getSection(name, type);
    return *sectionHeaders[0];
}

const Section &
Object::getSection(Word idx) const
{
    if (sectionHeaders[idx]->shdr.sh_type != SHT_NULL)
        return *sectionHeaders[idx];
    return *sectionHeaders[0];
}

const Section &
Object::getLinkedSection(const Section &from) const
{
    if (!from)
        return from;
    if (from.elf == this) // it might come from the debug object...
        return *sectionHeaders[from.shdr.sh_link];
    auto debug = getDebug();
    if (debug)
       return debug->getLinkedSection(from);
    return *sectionHeaders[0];
}

/*
 * Locate a named symbol in an ELF image - this uses the dynamic symbol table
 * which provides hash-accellerated access. (via either .hash or .gnu_hash
 * section)
 */
std::pair<Sym, size_t>
Object::findDynamicSymbol(const std::string &name)
{
    Sym sym;
    uint32_t idx;

    std::tie(idx, sym) = gnu_hash() ? gnu_hash()->findSymbol(name)
             : hash() ? hash()->findSymbol(name)
             : std::make_pair(uint32_t(0), undef());

    if (idx == 0)
        return { undef() , 0 };

    // We found a symbol in our hash table. Find its version if we can.
    return {sym, idx};
}

std::pair<Sym, size_t>
Object::findDebugSymbol(const string &name)
{
    // Cache all debug symbols the first time we scan them.
    //
    auto syms = debugSymbols();
    if (!cachedSymbols) {
       cachedSymbols = std::make_unique<std::map<std::string, size_t>>();
       size_t idx = 0;
       for (auto sym : syms->array)
          (*cachedSymbols)[syms->name(sym)] = idx++;
    }
    auto off = cachedSymbols->find(name);
    if (off != cachedSymbols->end())
       return { syms->symbols->readObj<Sym>(off->second * sizeof (Sym)), off->second };
    return {undef(), 0};
}

Object *
Object::getDebug() const
{
    if (debugLoaded || noExtDebug)
        return debugObject.get();
    debugLoaded = true;

    // Use the build ID to find debug data.
    for (const auto &note : notes()) {
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
            auto link = hdr.io()->readString(0);
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
            sect->shdr.sh_addr += diff;

        for (auto &sectType : debugObject->programHeaders)
            for (auto &sect : sectType.second)
                sect.p_vaddr += diff;
    }
    return debugObject.get();
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
    return std::make_pair(0, undef());
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

Section::Section(Object *elf, Off off) : elf(elf) {
    elf->io->readObj(off, &shdr);
}

Reader::csptr Section::io() const {
    if (io_ != nullptr)
        return io_;

    if (shdr.sh_type == SHT_NULL) {
        io_ = make_shared<NullReader>();
        return io_;
    }

    // deal with two possible zlib-compressed sections. The sane,
    // "SHF_COMPRESSED" version, and the hacky ".zdebug_" versions.
#ifndef WITH_ZLIB
    bool wantedZlib = false;
#endif

    auto rawIo = elf->io->view(name, shdr.sh_offset, shdr.sh_size);
    if ((shdr.sh_flags & SHF_COMPRESSED) != 0) {
#ifdef WITH_ZLIB
        auto chdr = rawIo->readObj<Chdr>(0);
        io_ = make_shared<InflateReader>(
              chdr.ch_size,
              *rawIo->view("ZLIB compressed content after chdr", sizeof chdr, shdr.sh_size - sizeof chdr));
#else
        wantedZlib = true;
#endif
    } else if (name.rfind(".zdebug_", 0) == 0) {
        unsigned char sig[12];
        rawIo->readObj(0, sig, sizeof sig);
        if (std::memcmp((const char *)sig, "ZLIB", 4) == 0) {
#ifdef WITH_ZLIB
            uint64_t sz = 0;
            for (size_t i = 4; i < 12; ++i) {
                sz <<= 8;
                sz |= sig[i];
            }
            io_ = make_shared<InflateReader>(
                  sz,
                  *rawIo->view("ZLIB compressed content after magic signature", sizeof sig, sz));
#else
            wantedZlib = true;
#endif
        }
    } else {
        io_ = rawIo;
    }
#ifndef WITH_ZLIB
    if (wantedZlib) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            std::clog <<"warning: no support configured for compressed debug info in section "
                << name << " of " << *elf->io << std::endl;
        }
    }
#endif
    if (io_ == nullptr)
        io_ = make_shared<NullReader>();
    return io_;
}

Object::sptr
ImageCache::getImageForName(const string &name, bool isDebug) {
    auto res = getImageIfLoaded(name);
    if (res != nullptr)
        return res;
    auto item = make_shared<Object>(*this, std::make_shared<MmapReader>(name), isDebug);
    // don't cache negative entries: assign into the cache after we've constructed:
    // a failure to load the image will throw.
    cache[name] = item;
    return item;
}

ImageCache::ImageCache() : elfHits(0), elfLookups(0) {}
ImageCache::~ImageCache() noexcept {
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
    for (const auto &dir : globalDebugDirectories) {
        auto img = getImageIfLoaded(stringify(dir, "/", name));
        if (img)
            return img;
    }
    for (const auto &dir : globalDebugDirectories) {
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

namespace {
struct Undef {
    Sym undefSym;
    Undef() {
        memset(&undefSym, 0, sizeof undefSym);
        undefSym.st_shndx = SHN_UNDEF;
    }
};
}

const Sym &undef() {
    static Undef theUndef;
    return theUndef.undefSym;
}

}
