#include <limits>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <libpstack/util.h>
#include <libpstack/elf.h>
#include <algorithm>

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
   return ElfNoteIter(object, object->getSegments().begin());
}

ElfNoteIter
ElfNotes::end() const
{
   return ElfNoteIter(object, object->getSegments().end());
}

std::string
ElfNoteDesc::name() const
{
   char *buf = new char[note.n_namesz + 1];
   object->io->readObj(offset + sizeof note, buf, note.n_namesz);
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
      object->io->readObj(roundup2(offset + sizeof note + note.n_namesz, 4),
            databuf, note.n_descsz);
   }
   return databuf;
}

size_t
ElfNoteDesc::size() const
{
   return note.n_descsz;
}

/*
 * Parse out an ELF file into an ElfObject structure.
 */

const Elf_Phdr *
ElfObject::findHeaderForAddress(Elf_Off a) const
{
    for (auto &hdr : programHeaders)
        if (hdr.p_vaddr <= a && hdr.p_vaddr + hdr.p_memsz > a && hdr.p_type == PT_LOAD)
            return &hdr;
    return 0;
}

ElfObject::ElfObject(const string &name_)
    : name(name_)
    , notes(this)
{
    init(make_shared<CacheReader>(make_shared<FileReader>(name)));
}

ElfObject::ElfObject(shared_ptr<Reader> io_)
   : notes(this)
{
    name = io_->describe();
    init(io_);
}

Elf_Addr
ElfObject::getBase() const
{
    auto base = std::numeric_limits<Elf_Off>::max();
    auto &segments = getSegments();
    for (auto &seg : segments)
        if (seg.p_type == PT_LOAD && Elf_Off(seg.p_vaddr) <= base)
            base = Elf_Off(seg.p_vaddr);
    return base;
}

std::string
ElfObject::getInterpreter() const
{
    for (auto &seg : getSegments())
        if (seg.p_type == PT_INTERP)
            return io->readString(seg.p_offset);
    return "";
}

void
ElfObject::init(const shared_ptr<Reader> &io_)
{
    debugLoaded = false;
    io = io_;
    int i;
    size_t off;
    io->readObj(0, &elfHeader);

    /* Validate the ELF header */
    if (!IS_ELF(elfHeader) || elfHeader.e_ident[EI_VERSION] != EV_CURRENT)
        throw Exception() << io->describe() << ": content is not an ELF image";

    for (off = elfHeader.e_phoff, i = 0; i < elfHeader.e_phnum; i++) {
        programHeaders.push_back(Elf_Phdr());
        io->readObj(off, &programHeaders.back());
        off += elfHeader.e_phentsize;
    }

    for (off = elfHeader.e_shoff, i = 0; i < elfHeader.e_shnum; i++) {
        sectionHeaders.push_back(Elf_Shdr());
        io->readObj(off, &sectionHeaders.back());
        off += elfHeader.e_shentsize;
    }

    if (elfHeader.e_shstrndx != SHN_UNDEF) {
        auto sshdr = sectionHeaders[elfHeader.e_shstrndx];
        for (auto &h : sectionHeaders) {
            auto name = io->readString(sshdr.sh_offset + h.sh_name);
            namedSection[name] = &h;
        }
        auto tab = getSection(".hash", SHT_HASH);
        if (tab)
            hash.reset(new ElfSymHash(tab));
    } else {
        hash = 0;
    }
}

std::pair<const Elf_Sym, const string>
SymbolIterator::operator *()
{
        Elf_Sym sym;
        io->readObj(off, &sym);
        string name = io->readString(sym.st_name + stroff);
        return std::make_pair(sym, name);
}

/*
 * Find the symbol that represents a particular address.
 * If we fail to find a symbol whose virtual range includes our target address
 * we will accept a symbol with the highest address less than or equal to our
 * target. This allows us to match the dynamic "stubs" in code.
 * A side-effect is a few false-positives: A stripped, dynamically linked,
 * executable will typically report functions as being "_init", because it is
 * the only symbol in the image, and it has no size.
 */
bool
ElfObject::findSymbolByAddress(Elf_Addr addr, int type, Elf_Sym &sym, string &name)
{
    /* Try to find symbols in these sections */
    static const char *sectionNames[] = {
        ".symtab", ".dynsym", 0
    };
    bool exact = false;
    Elf_Addr lowest = 0;
    for (size_t i = 0; sectionNames[i] && !exact; i++) {
        const auto symSection = getSection(sectionNames[i], SHT_NULL);
        if (symSection == 0 || symSection->sh_type == SHT_NOBITS)
            continue;
        SymbolSection syms(symSection);
        for (auto syminfo : syms) {
            auto &candidate = syminfo.first;
            if (candidate.st_shndx >= sectionHeaders.size())
                continue;
            auto shdr = sectionHeaders[candidate.st_shndx];
            if (!(shdr.sh_flags & SHF_ALLOC))
                continue;
            if (type != STT_NOTYPE && ELF_ST_TYPE(candidate.st_info) != type)
                continue;
            if (candidate.st_value > addr)
                continue;
            if (candidate.st_size) {
                // symbol has a size: we can check if our address lies within it.
                if (candidate.st_size + candidate.st_value > addr) {
                    // yep: return this one.
                    sym = candidate;
                    name = syminfo.second;
                    return true;
                }
            } else if (lowest < candidate.st_value) {
                /*
                 * No size, but hold on to it as a possibility. We'll return
                 * the symbol with the highest value not aabove the required
                 * value
                 */
                sym = candidate;
                name = syminfo.second;
                lowest = candidate.st_value;
            }
        }
    }
    return lowest != 0;
}

const ElfSection
ElfObject::getSection(const std::string &name, Elf_Word type)
{

    auto s = namedSection.find(name);
    return ElfSection(*this, s != namedSection.end() && (s->second->sh_type == type || type == SHT_NULL) ? s->second : 0);
}

SymbolSection
ElfObject::getSymbols(const std::string &table)
{
    return SymbolSection(getSection(table, SHT_NULL));
}

bool
linearSymSearch(ElfSection &section, const string &name, Elf_Sym &sym)
{
    SymbolSection sec(section);
    for (const auto &info : sec) {
        if (name == info.second) {
            sym = info.first;
            return true;
        }
    }
    return false;
}

ElfSymHash::ElfSymHash(ElfSection &hash_)
    : hash(hash_)
    , syms(hash.obj, hash.getLink())
{
    // read the hash table into local memory.
    size_t words = hash->sh_size / sizeof (Elf_Word);
    data.resize(words);
    hash.obj.io->readObj(hash->sh_offset, &data[0], words);
    nbucket = data[0];
    nchain = data[1];
    buckets = &data[0] + 2;
    chains = buckets + nbucket;
    strings = syms.getLink()->sh_offset;
}

bool
ElfSymHash::findSymbol(Elf_Sym &sym, const string &name)
{
    uint32_t bucket = elf_hash(name) % nbucket;
    for (Elf_Word i = buckets[bucket]; i != STN_UNDEF; i = chains[i]) {
        Elf_Sym candidate;
        syms.obj.io->readObj(syms->sh_offset + i * sizeof candidate, &candidate);
        string candidateName = syms.obj.io->readString(strings + candidate.st_name);
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
    auto dyn = getSection(".dynsym", SHT_DYNSYM);
    if (dyn && linearSymSearch(dyn, name, sym))
        return true;
    auto symtab = getSection(".symtab", SHT_SYMTAB);
    return symtab && linearSymSearch(symtab, name, sym);
}

/*
 * Get the data and length from a specific "note" in the ELF file
 */
#ifdef __FreeBSD__
/*
 * Try to work out the name of the executable from a core file
 * XXX: This is not particularly useful, because the pathname appears to get
 * stripped.
 */
static enum NoteIter
elfImageNote(void *cookie, const char *name, u_int32_t type,
        const void *data, size_t len)
{
    const char **exename;
    const prpsinfo_t *psinfo;

    exename = (const char **)cookie;
    psinfo = (const prpsinfo_t *)data;

    if (!strcmp(name, "FreeBSD") && type == NT_PRPSINFO &&
        psinfo->pr_version == PRPSINFO_VERSION) {
        *exename = psinfo->pr_fname;
        return NOTE_DONE;
    }
    return NOTE_CONTIN;
}

#endif

ElfObject::~ElfObject()
{
}

std::shared_ptr<ElfObject>
ElfObject::getDebug(std::shared_ptr<ElfObject> &in)
{
   auto sp = in->getDebug();
   return sp ? sp : in;
}

static std::shared_ptr<ElfObject>
tryLoad(const std::string &name) {
    // XXX: verify checksum.
    for (auto dir : globalDebugDirectories.dirs) {
        try {
           auto debugObject = make_shared<ElfObject>(dir + "/" + name);
           if (verbose >= 2)
              *debug << "found debug object " << dir << "/" << name << "\n";
           return debugObject;
        }
        catch (const std::exception &ex) {
            continue;
        }
    }
    if (verbose >= 2)
        *debug << "no file found for " << name << std::endl;
    return std::shared_ptr<ElfObject>();
}

std::shared_ptr<ElfObject>
ElfObject::getDebug()
{
    if (noDebugLibs)
        return std::shared_ptr<ElfObject>();

    if (!debugLoaded) {
        debugLoaded = true;

        std::ostringstream stream;
        stream << io->describe();
        std::string oldname = stream.str();

        auto hdr = getSection(".gnu_debuglink", SHT_PROGBITS);
        if (hdr == 0)
            return std::shared_ptr<ElfObject>();
        std::vector<char> buf(hdr->sh_size);
        std::string link = io->readString(hdr->sh_offset);

        auto dir = dirname(oldname);
        debugObject = tryLoad(dir + "/" + link);
        if (!debugObject) {
            for (auto note : notes) {
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
                    debugObject = tryLoad(dir.str());
                    break;
                }
            }
        }
    }
    return debugObject;
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

const Elf_Shdr *ElfSection::getLink() const
{
    return &obj.sectionHeaders[shdr->sh_link];
}
