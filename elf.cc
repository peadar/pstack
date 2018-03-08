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

using std::string;
using std::make_shared;
using std::shared_ptr;

std::ostream *debug = &std::clog;
int verbose = 0;
static uint32_t elf_hash(const string &text);
bool noDebugLibs;

GlobalDebugDirectories globalDebugDirectories;
GlobalDebugDirectories::GlobalDebugDirectories() throw()
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
   return io->readString(sizeof note);
}

std::shared_ptr<const Reader>
ElfNoteDesc::data() const
{
   return std::make_shared<OffsetReader>(io, sizeof note + roundup2(note.n_namesz, 4), note.n_descsz);
}

size_t
ElfNoteDesc::size() const
{
   return note.n_descsz;
}


ElfObject::ElfObject(ImageCache &cache, shared_ptr<const Reader> io_)
    : io(std::move(io_))
    , notes(this)
    , elfHeader(io->readObj<Elf_Ehdr>(0))
    , imageCache(cache)
{
    debugLoaded = false;
    int i;
    size_t off;

    /* Validate the ELF header */
    if (!IS_ELF(elfHeader) || elfHeader.e_ident[EI_VERSION] != EV_CURRENT)
        throw (Exception() << *io << ": content is not an ELF image");

    for (off = elfHeader.e_phoff, i = 0; i < elfHeader.e_phnum; i++) {
        auto hdr = io->readObj<Elf_Phdr>(off);
        programHeaders[hdr.p_type].push_back(hdr);
        off += elfHeader.e_phentsize;
    }

    sectionHeaders.resize(elfHeader.e_shnum);
    for (off = elfHeader.e_shoff, i = 0; i < elfHeader.e_shnum; i++) {
        sectionHeaders[i].open(io, off);
        off += elfHeader.e_shentsize;
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
                debugData = std::make_shared<ElfObject>(imageCache,
                      std::make_shared<const LzmaReader>(h.io));
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
        auto &syms = getSection(tab.shdr.sh_link);
        auto &strings = getSection(syms.shdr.sh_link);
        if (tab && syms && strings)
            hash = std::make_unique<ElfSymHash>(tab.io, syms.io, strings.io);
    } else {
        hash = nullptr;
    }
}

const Elf_Phdr *
ElfObject::getSegmentForAddress(Elf_Off a) const
{
    for (const auto &hdr : getSegments(PT_LOAD))
        if (hdr.p_vaddr <= a && hdr.p_vaddr + hdr.p_memsz > a)
            return &hdr;
    return nullptr;
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
    auto sym = sec->symbols->readObj<Elf_Sym>(off);
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
        const auto &symSection = getSection(secname, SHT_NULL);
        if (symSection.shdr.sh_type == SHT_NOBITS)
            continue;
        SymbolSection syms(symSection.io, getSection(symSection.shdr.sh_link).io);
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

const ElfSection &
ElfObject::getSection(const std::string &name, Elf_Word type) const
{
    auto s = namedSection.find(name);
    if (s == namedSection.end() || (s->second->shdr.sh_type != type && type != SHT_NULL))
        return sectionHeaders[0];
    return *s->second;
}

const ElfSection &
ElfObject::getSection(Elf_Word idx) const
{
    return sectionHeaders[idx];
}

SymbolSection
ElfObject::getSymbols(const std::string &tableName)
{
    auto &table = getSection(tableName, SHT_NULL);
    std::string n = stringify(*io);
    if (table.shdr.sh_type == SHT_NOBITS || table.shdr.sh_type == SHT_NULL)
        return SymbolSection(sectionHeaders[0].io, sectionHeaders[0].io);
    auto &strings = getSection(table.shdr.sh_link);
    return SymbolSection(table.io, strings.io);
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

ElfSymHash::ElfSymHash(std::shared_ptr<const Reader> hash_,
      std::shared_ptr<const Reader> syms_, std::shared_ptr<const Reader> strings_)
    : hash(std::move(hash_))
    , syms(std::move(syms_))
    , strings(std::move(strings_))
{
    // read the hash table into local memory.
    size_t words = hash->size() / sizeof (Elf_Word);
    data.resize(words);
    hash->readObj(0, &data[0], words);
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
        auto candidate = syms->readObj<Elf_Sym>(i * sizeof (Elf_Sym));
        auto candidateName = strings->readString(candidate.st_name);
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
    if (hash && hash->findSymbol(sym, name))
        return true;

    for (const char *sec : { ".dynsym", ".symtab" }) {
        SymbolSection sect = getSymbols(sec);
        if (sect.linearSearch(name, sym))
            return true;
    }
    return debugData ? debugData->findSymbolByName(name, sym) : false;
}

ElfObject::~ElfObject() = default;

std::shared_ptr<ElfObject>
ElfObject::getDebug(std::shared_ptr<ElfObject> &in)
{
    if (noDebugLibs)
        return in;

    if (!in->debugLoaded) {
        in->debugLoaded = true;
        auto &hdr = in->getSection(".gnu_debuglink", SHT_PROGBITS);
        if (!hdr)
           return in;
        auto link = hdr.io->readString(0);
        auto dir = dirname(stringify(*in->io));
        in->debugObject = in->imageCache.getDebugImage(dir + "/" + link);

        if (!in->debugObject) {
            for (auto note : in->notes) {
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


void
ElfSection::open(const std::shared_ptr<const Reader> &image, off_t off)
{
    image->readObj(off, &shdr);

    // Null sections get null readers.
    if (shdr.sh_type == SHT_NULL) {
        io = std::make_shared<NullReader>();
        return;
    }

    auto rawIo = std::make_shared<OffsetReader>(image, shdr.sh_offset, shdr.sh_size);
    if ((shdr.sh_flags & SHF_COMPRESSED) == 0) {
        io = rawIo;
    } else {

#ifdef WITH_ZLIB
        auto chdr = rawIo->readObj<Elf_Chdr>(0);
        io = std::make_shared<InflateReader>(chdr.ch_size,
              OffsetReader(rawIo, sizeof chdr, shdr.sh_size - sizeof chdr));
#else
        static bool warned = false;
        if (!warned) {
            warned = true;
            std::clog <<"warning: no support configured for compressed debug info in " << *image << std::endl;
        }
        io = std::make_shared<NullReader>();
#endif
    }
}

std::shared_ptr<ElfObject>
ImageCache::getImageForName(const std::string &name) {
    bool found;
    auto res = getImageIfLoaded(name, found);
    if (found) {
        if (res != nullptr)
            return res;
        // Don't return null to keep it consistent with a previous failure to load.
        throw (Exception() << "previously failed to load " << name);
    }
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
    return std::shared_ptr<ElfObject>();
}
