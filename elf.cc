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

size_t
NoteDesc::size() const
{
   return note.n_descsz;
}

std::pair<const Sym, const string>
SymbolIterator::operator *()
{
    auto sym = sec->symbols->readObj<Sym>(off);
    string name = sec->strings->readString(sym.st_name);
    return std::make_pair(sym, name);
}

Object::Object(ImageCache &cache, Reader::csptr io_)
    : io(std::move(io_))
    , notes(this)
    , elfHeader(io->readObj<Ehdr>(0))
    , imageCache(cache)
    , lastSegmentForAddress(nullptr)
{
    debugLoaded = false;
    int i;
    size_t off;

    /* Validate the ELF header */
    if (!IS_ELF(elfHeader) || elfHeader.e_ident[EI_VERSION] != EV_CURRENT)
        throw (Exception() << *io << ": content is not an ELF image");

    OffsetReader headers(io, elfHeader.e_phoff, elfHeader.e_phnum * sizeof (Phdr));
    for (auto hdr : ReaderArray<Phdr>(headers))
        programHeaders[hdr.p_type].push_back(hdr);

    for (auto &phdrs : programHeaders) {
        std::sort(phdrs.second.begin(), phdrs.second.end(), [] (const Phdr &lhs, const Phdr &rhs) { return lhs.p_vaddr < rhs.p_vaddr; });
    }

    if (elfHeader.e_shnum == 0) {
        sectionHeaders.emplace_back();
    } else {
        for (off = elfHeader.e_shoff, i = 0; i < elfHeader.e_shnum; i++) {
            sectionHeaders.emplace_back(io, off);
            off += elfHeader.e_shentsize;
        }
    }

    if (elfHeader.e_shstrndx != SHN_UNDEF) {
        auto &sshdr = sectionHeaders[elfHeader.e_shstrndx];
        for (auto &h : sectionHeaders) {
            auto name = sshdr.io->readString(h.shdr.sh_name);
            namedSection[name] = &h;
            // .gnu_debugdata is a separate LZMA-compressed ELF image with just
            // a symbol table.
            if (name == ".gnu_debugdata") {
#ifdef WITH_LZMA
                debugData = make_shared<Object>(imageCache,
                      make_shared<const LzmaReader>(h.io));
#else
                static bool warned = false;
                if (!warned) {
                    std::clog << "warning: no compiled support for LZMA - "
                          "can't decode debug data in " << *io << "\n";
                    warned = true;
                }
#endif
            }
        }
        auto &tab = getSection(".hash", SHT_HASH);
        auto &syms = getLinkedSection(tab);
        auto &strings = getLinkedSection(syms);
        if (tab && syms && strings)
            hash = make_unique<SymHash>(tab.io, syms.io, strings.io);
    } else {
        hash = nullptr;
    }
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
    for (auto secname : { ".symtab", ".dynsym" }) {
        const auto &symSection = getSection(secname, SHT_NULL);
        if (symSection.shdr.sh_type == SHT_NOBITS)
            continue;
        SymbolSection syms(symSection.io, getLinkedSection(symSection).io);
        for (auto syminfo : syms) {
            auto &candidate = syminfo.first;
            if (candidate.st_shndx >= sectionHeaders.size())
                continue;
            if (type != STT_NOTYPE && ELF_ST_TYPE(candidate.st_info) != type)
                continue;
            if (candidate.st_value > addr)
                continue;
            if (candidate.st_size + candidate.st_value <= addr)
                continue;
            auto &sec = sectionHeaders[candidate.st_shndx];
            if ((sec.shdr.sh_flags & SHF_ALLOC) == 0)
                continue;
            sym = candidate;
            name = syminfo.second;
            return true;
        }
    }
    if (debugData)
        return debugData->findSymbolByAddress(addr, type, sym, name);
    return false;;
}

const Section &
Object::getSection(const string &name, Word type) const
{
    auto s = namedSection.find(name);
    if (s == namedSection.end() || (s->second->shdr.sh_type != type && type != SHT_NULL)) {
        Object *debug = getDebug();
        if (debug)
            return debug->getSection(name, type);
        return sectionHeaders[0];
    }
    return *s->second;
}

const Section &
Object::getSection(Word idx) const
{
    if (sectionHeaders[idx].shdr.sh_type != SHT_NULL)
        return sectionHeaders[idx];
    auto debug = getDebug();
    if (debug) {
        return debug->sectionHeaders[idx];
    }
    return sectionHeaders[0];
}

const Section &
Object::getLinkedSection(const Section &from) const
{
    if (&from >= &sectionHeaders[0] && &from <= &sectionHeaders[sectionHeaders.size() - 1])
        return sectionHeaders[from.shdr.sh_link];
    return getDebug()->sectionHeaders[from.shdr.sh_link];
}

SymbolSection
Object::getSymbols(const string &tableName)
{
    auto &table = getSection(tableName, SHT_NULL);
    string n = stringify(*io);
    if (table.shdr.sh_type == SHT_NOBITS || table.shdr.sh_type == SHT_NULL)
        return SymbolSection(sectionHeaders[0].io, sectionHeaders[0].io);
    auto &strings = getLinkedSection(table);
    return SymbolSection(table.io, strings.io);
}

/*
 * Locate a named symbol in an ELF image.
 */
bool
Object::findSymbolByName(const string &name, Sym &sym)
{
    auto &syment = cachedSymbols[name];
    auto findUncached  = [&](Sym &sym) {
        if (hash && hash->findSymbol(sym, name))
            return CachedSymbol::SYM_FOUND;
        for (const char *sec : { ".dynsym", ".symtab" }) {
            SymbolSection sect = getSymbols(sec);
            if (sect.linearSearch(name, sym))
                return CachedSymbol::SYM_FOUND;
        }
        return CachedSymbol::SYM_NOTFOUND;
    };
    if (syment.disposition == CachedSymbol::SYM_NEW)
        syment.disposition = findUncached(syment.sym);
    if (syment.disposition == CachedSymbol::SYM_FOUND) {
        sym = syment.sym;
        return true;
    }
    if (debugData)
        return debugData->findSymbolByName(name, sym);
    return false;
}

Object::~Object() = default;

Object *
Object::getDebug() const
{
    if (!debugLoaded) {
        debugLoaded = true;
        auto &hdr = getSection(".gnu_debuglink", SHT_PROGBITS);
        if (!hdr)
            return 0;
        auto link = hdr.io->readString(0);
        auto dir = dirname(stringify(*io));
        debugObject = imageCache.getDebugImage(dir + "/" + link);
        if (!debugObject) {
            for (auto note : notes) {
                if (note.name() == "GNU" && note.type() == GNU_BUILD_ID) {
                    std::ostringstream dir;
                    dir << ".build-id/";
                    size_t i;
                    auto io = note.data();
                    std::vector<unsigned char> data(io->size());
                    io->readObj(0, &data[0], io->size());
                    dir << std::hex << std::setw(2) << std::setfill('0') << int(data[0]);
                    dir << "/";
                    for (i = 1; i < note.size(); ++i)
                        dir << std::setw(2) << int(data[i]);
                    dir << ".debug";
                    debugObject = imageCache.getDebugImage(dir.str());
                    break;
                }
            }
        }
        if (debugObject && verbose >= 2)
            *debug << "found debug object " << *debugObject->io << " for " << *io << "\n";
    }
    return debugObject.get();
}

bool
SymbolSection::linearSearch(const string &name, Sym &sym)
{
    for (const auto &info : *this) {
        if (name == info.second) {
            sym = info.first;
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

bool
SymHash::findSymbol(Sym &sym, const string &name)
{
    uint32_t bucket = elf_hash(name) % nbucket;
    for (Word i = buckets[bucket]; i != STN_UNDEF; i = chains[i]) {
        auto candidate = syms->readObj<Sym>(i * sizeof (Sym));
        auto candidateName = strings->readString(candidate.st_name);
        if (candidateName == name) {
            sym = candidate;
            return true;
        }
    }
    return false;
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

Section::Section(const Reader::csptr &image, off_t off)
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
ImageCache::getImageForName(const string &name) {
    bool found;
    auto res = getImageIfLoaded(name, found);
    if (found) {
        if (res != nullptr)
            return res;
        // Don't return null to keep it consistent with a previous failure to load.
        throw (Exception() << "previously failed to load " << name);
    }
    auto item = make_shared<Object>(*this, loadFile(name));
    // don't cache negative entries: assign into the cache after we've constructed:
    // a failure to load the image will throw.
    cache[name] = item;
    return item;
}

ImageCache::ImageCache() : elfHits(0), elfLookups(0) {}
ImageCache::~ImageCache() {
    if (verbose >= 2) {
        *debug << "ELF image cache: lookups: " << elfLookups << ", hits=" << elfHits << std::endl;
        for (auto &items : cache) {
            if (items.second)
                *debug << "\t" << *items.second->io << std::endl;
            else
                *debug << "\t" << "NEGATIVE: " << items.first << std::endl;
        }
    }
}

Object::sptr
ImageCache::getImageIfLoaded(const string &name, bool &found)
{
    elfLookups++;
    auto it = cache.find(name);
    if (it != cache.end()) {
        elfHits++;
        found = true;
        return it->second;
    }
    found = false;
    return Object::sptr();
}

Object::sptr
ImageCache::getDebugImage(const string &name) {
    // XXX: verify checksum.
    for (const auto &dir : globalDebugDirectories.dirs) {
        bool found;
        auto img = getImageIfLoaded(stringify(dir, "/", name), found);
        if (found)
            return img;
    }
    for (const auto &dir : globalDebugDirectories.dirs) {
        try {
           return getImageForName(stringify(dir, "/", name));
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
}
