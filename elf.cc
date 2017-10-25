#include <limits>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <algorithm>

#include "libpstack/util.h"
#include "libpstack/elf.h"
#ifdef WITH_ZLIB
#include "libpstack/inflatereader.h"
#endif
#ifdef WITH_LZMA
#include "libpstack/lzmareader.h"
#endif

using std::string;
using std::make_shared;
using std::shared_ptr;

std::ostream *debug = &std::clog;
int verbose = 0;
static uint32_t elf_hash(string);
bool noDebugLibs;

GlobalDebugDirectories globalDebugDirectories;
GlobalDebugDirectories::GlobalDebugDirectories()
{
   add("/usr/lib/debug");
   add("/usr/lib/debug/usr"); // Add as a hack for when linker loads from /lib, but package has /usr/lib
}

void
GlobalDebugDirectories::add(const std::string &str)
{
   dirs.push_back(str);
}

ElfNoteIter
ElfNotes::begin() const
{
   return ElfNoteIter(object, true);
}

ElfNoteIter
ElfNotes::end() const
{
   return ElfNoteIter(object, false);
}

std::string
ElfNoteDesc::name() const
{
   char *buf = new char[note.n_namesz + 1];
   io->readObj(sizeof note, buf, note.n_namesz);
   buf[note.n_namesz] = 0;
   std::string s = buf;
   delete[] buf;
   return s;
}

const unsigned char *
ElfNoteDesc::data() const
{
   if (databuf == 0) {
      databuf = new unsigned char[note.n_descsz];
      io->readObj(roundup2(sizeof note + note.n_namesz, 4), databuf, note.n_descsz);
   }
   return databuf;
}

size_t
ElfNoteDesc::size() const
{
   return note.n_descsz;
}

ElfObject::ElfObject(ImageCache &cache, shared_ptr<Reader> io_)
   : notes(this)
   , imageCache(cache)
{
    debugLoaded = false;
    io = io_;
    int i;
    size_t off;
    io->readObj(0, &elfHeader);

    /* Validate the ELF header */
    if (!IS_ELF(elfHeader) || elfHeader.e_ident[EI_VERSION] != EV_CURRENT)
        throw Exception() << *io << ": content is not an ELF image";

    for (off = elfHeader.e_phoff, i = 0; i < elfHeader.e_phnum; i++) {
        Elf_Phdr hdr;
        io->readObj(off, &hdr);
        programHeaders[hdr.p_type].push_back(hdr);
        off += elfHeader.e_phentsize;
    }

    for (off = elfHeader.e_shoff, i = 0; i < elfHeader.e_shnum; i++) {
        sectionHeaders.push_back(std::make_shared<ElfSection>(*this, off));
        off += elfHeader.e_shentsize;
    }

    if (elfHeader.e_shstrndx != SHN_UNDEF) {
        auto sshdr = sectionHeaders[elfHeader.e_shstrndx];
        for (auto &h : sectionHeaders) {
            auto name = sshdr->io->readString(h->shdr.sh_name);
            namedSection[name] = h;
            // .gnu_debugdata is a separate LZMA-compressed ELF image with just
            // a symbol table.
            if (name == ".gnu_debugdata")
#ifdef WITH_LZMA
                debugData = std::make_shared<ElfObject>(imageCache,
                      std::make_shared<LzmaReader>(h->io));
#else
                std::clog << "warning: no compiled support for LZMA - "
                      "can't decode debug data in " << *io << "\n";
#endif
        }
        auto tab = getSection(".hash", SHT_HASH);
        if (tab) {
            auto syms = getSection(tab->shdr.sh_link);
            if (syms) {
               auto strings = getSection(syms->shdr.sh_link);
               if (strings)
                  hash.reset(new ElfSymHash(tab, syms, strings));
            }
        }
    } else {
        hash = 0;
    }
}

const Elf_Phdr *
ElfObject::getSegmentForAddress(Elf_Off a) const
{
    for (const auto &hdr : getSegments(PT_LOAD))
        if (hdr.p_vaddr <= a && hdr.p_vaddr + hdr.p_memsz > a)
            return &hdr;
    return 0;
}

const ElfObject::ProgramHeaders &
ElfObject::getSegments(Elf_Word type) const
{
    auto it = programHeaders.find(type);
    if (it == programHeaders.end()) {
        static const ProgramHeaders empty;
        return empty;
    }
    return it->second;
}

Elf_Addr
ElfObject::getBase() const
{
    auto base = std::numeric_limits<Elf_Off>::max();
    auto &segments = getSegments(PT_LOAD);
    for (auto &seg : segments)
        if (Elf_Off(seg.p_vaddr) <= base)
            base = Elf_Off(seg.p_vaddr);
    return base;
}

std::string
ElfObject::getInterpreter() const
{
    for (auto &seg : getSegments(PT_INTERP))
        return io->readString(seg.p_offset);
    return "";
}

std::pair<const Elf_Sym, const string>
SymbolIterator::operator *()
{
    Elf_Sym sym;
    sec->symbols->readObj(off, &sym);
    string name = sec->strings->readString(sym.st_name);
    return std::make_pair(sym, name);
}

/*
 * Find the symbol that represents a particular address.
 */
bool
ElfObject::findSymbolByAddress(Elf_Addr addr, int type, Elf_Sym &sym, string &name)
{
    /* Try to find symbols in these sections */
    for (auto secname : { ".symtab", ".dynsym" }) {
        const auto symSection = getSection(secname, SHT_NULL);
        if (symSection == 0 || symSection->shdr.sh_type == SHT_NOBITS)
            continue;
        SymbolSection syms(symSection->io, getSection(symSection->shdr.sh_link)->io);
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
            auto sec = sectionHeaders[candidate.st_shndx];
            if (!(sec->shdr.sh_flags & SHF_ALLOC))
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

std::shared_ptr<const ElfSection>
ElfObject::getSection(const std::string &name, Elf_Word type) const
{
    auto s = namedSection.find(name);
    if (s == namedSection.end() || (s->second->shdr.sh_type != type && type != SHT_NULL))
        return nullptr;
    return s->second;
}

std::shared_ptr<const ElfSection>
ElfObject::getSection(Elf_Word idx) const
{
    return sectionHeaders[idx];
}

SymbolSection
ElfObject::getSymbols(const std::string &tableName)
{
    ElfObject *elf = debugData ? debugData.get() : this;
    auto table = elf->getSection(tableName, SHT_NULL);
    if (table) {
        auto strings = elf->getSection(table->shdr.sh_link);
        if (strings)
           return SymbolSection(table->io, strings->io);
    }
    return SymbolSection(nullptr, nullptr);
}

bool
SymbolSection::linearSearch(const string &name, Elf_Sym &sym)
{
    for (const auto &info : *this) {
        if (name == info.second) {
            sym = info.first;
            return true;
        }
    }
    return false;
}

ElfSymHash::ElfSymHash(std::shared_ptr<const ElfSection> &hash_, std::shared_ptr<const ElfSection> &syms_, std::shared_ptr<const ElfSection> &strings_)
    : hash(hash_)
    , syms(syms_)
    , strings(strings_)
{
    // read the hash table into local memory.
    size_t words = hash->io->size() / sizeof (Elf_Word);
    data.resize(words);
    hash->io->readObj(0, &data[0], words);
    nbucket = data[0];
    nchain = data[1];
    buckets = &data[0] + 2;
    chains = buckets + nbucket;
}

bool
ElfSymHash::findSymbol(Elf_Sym &sym, const string &name)
{
    uint32_t bucket = elf_hash(name) % nbucket;
    for (Elf_Word i = buckets[bucket]; i != STN_UNDEF; i = chains[i]) {
        Elf_Sym candidate;
        syms->io->readObj(i * sizeof candidate, &candidate);
        string candidateName = strings->io->readString(candidate.st_name);
        if (candidateName == name) {
            sym = candidate;
            return true;
        }
    }
    return false;
}

/*
 * Locate a named symbol in an ELF image.
 */
bool
ElfObject::findSymbolByName(const string &name, Elf_Sym &sym)
{
    if (debugData)
        return debugData->findSymbolByName(name, sym);

    if (hash && hash->findSymbol(sym, name))
        return true;

    {
        SymbolSection sect = getSymbols(".dynsym");
        if (sect.linearSearch(name, sym))
            return true;
    }

    {
        SymbolSection sect = getSymbols(".symtab");
        if (sect.linearSearch(name, sym))
            return true;
    }

    return false;
}

ElfObject::~ElfObject()
{
}

std::shared_ptr<ElfObject>
ElfObject::getDebug(std::shared_ptr<ElfObject> &in)
{
    if (noDebugLibs)
        return in;

    if (!in->debugLoaded) {
        in->debugLoaded = true;
        auto hdr = in->getSection(".gnu_debuglink", SHT_PROGBITS);
        if (hdr) {
            std::string link = hdr->io->readString(0);
            auto dir = dirname(stringify(*in->io));
            in->debugObject = in->imageCache.getDebugImage(dir + "/" + link);
        }

        if (!in->debugObject) {
            for (auto note : in->notes) {
                if (note.name() == "GNU" && note.type() == GNU_BUILD_ID) {
                    std::ostringstream dir;
                    dir << ".build-id/";
                    size_t i;
                    auto data = note.data();
                    dir << std::hex << std::setw(2) << std::setfill('0') << int(data[0]);
                    dir << "/";
                    for (i = 1; i < note.size(); ++i)
                        dir << std::setw(2) << int(data[i]);
                    dir << ".debug";
                    in->debugObject = in->imageCache.getDebugImage(dir.str());
                    break;
                }
            }
        }
        if (in->debugObject && verbose >= 2)
            *debug << "found debug object " << *in->debugObject->io << " for " << *in->io << "\n";
    }
    return in->debugObject ? in->debugObject : in;
}

/*
 * Culled from System V Application Binary Interface
 */
static uint32_t
elf_hash(string name)
{
    uint32_t h = 0, g;
    for (auto c : name) {
        h = (h << 4) + c;
        if ((g = h & 0xf0000000) != 0)
            h ^= g >> 24;
        h &= ~g;
    }
    return (h);
}

ElfSection::ElfSection(const ElfObject &obj_, off_t off)
{
    obj_.io->readObj(off, &shdr);
    auto rawIo = std::make_shared<OffsetReader>(obj_.io, shdr.sh_offset, shdr.sh_size);
    if (shdr.sh_flags & SHF_COMPRESSED) {
#ifdef WITH_ZLIB
        Elf_Chdr chdr;
        rawIo->readObj(0, &chdr);
        io = std::make_shared<InflateReader>(chdr.ch_size,
              std::make_shared<OffsetReader>(rawIo,
                 sizeof chdr, shdr.sh_size - sizeof chdr));
#else
        std::clog <<"warning: no support configured for compressed debug info in "
           << obj_.io << std::endl;
#endif
    } else {
        io = rawIo;
    }
}

std::shared_ptr<ElfObject>
ImageCache::getImageForName(const std::string &name) {
    bool found;
    auto res = getImageIfLoaded(name, found);
    if (found)
        return res;
    auto &item = cache[name];
    item = std::make_shared<ElfObject>(*this, loadFile(name));
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

std::shared_ptr<ElfObject>
ImageCache::getImageIfLoaded(const std::string &name, bool &found)
{
    elfLookups++;
    auto it = cache.find(name);
    if (it != cache.end()) {
        elfHits++;
        found = true;
        return it->second;
    }
    found = false;
    return std::shared_ptr<ElfObject>();
}

std::shared_ptr<ElfObject>
ImageCache::getDebugImage(const std::string &name) {
    // XXX: verify checksum.
    for (auto dir : globalDebugDirectories.dirs) {
        bool found;
        auto img = getImageIfLoaded(dir + "/" + name, found);
        if (found)
            return img;
    }
    for (auto dir : globalDebugDirectories.dirs) {
        try {
           return getImageForName(dir + "/" + name);
        }
        catch (const std::exception &ex) {
            continue;
        }
    }
    return std::shared_ptr<ElfObject>();
}
