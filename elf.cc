#include <limits>
#include "elfinfo.h"

std::ostream *debug;
static uint32_t elf_hash(std::string);

/*
 * Parse out an ELF file into an ElfObject structure.
 */

const std::shared_ptr<Elf_Phdr>
ElfObject::findHeaderForAddress(Elf_Off a) const
{
    for (auto &hdr : programHeaders)
        if (hdr->p_vaddr <= a && hdr->p_vaddr + hdr->p_memsz > a && hdr->p_type == PT_LOAD)
            return hdr;
    return 0;
}

ElfObject::ElfObject(std::shared_ptr<Reader> io_)
    : io(std::shared_ptr<Reader>(new CacheReader(io_)))
    , dynamic(0)
{
    int i;
    size_t off;
    io->readObj(0, &elfHeader);

    /* Validate the ELF header */
    if (!IS_ELF(elfHeader) || elfHeader.e_ident[EI_VERSION] != EV_CURRENT)
        throw Exception() << io->describe() << ": content is not an ELF image";

    base = std::numeric_limits<Elf_Off>::max();
    for (off = elfHeader.e_phoff, i = 0; i < elfHeader.e_phnum; i++) {
        Elf_Phdr *phdr = new Elf_Phdr();
        io->readObj(off, phdr);

        switch (phdr->p_type) {
            case PT_INTERP:
                interpreterName = io->readString(phdr->p_offset);
                break;
            case PT_DYNAMIC:
                dynamic = phdr;
                break;
            case PT_LOAD:
                if (Elf_Off(phdr->p_vaddr) <= base)
                    base = Elf_Off(phdr->p_vaddr);
                break;
        }
        programHeaders.push_back(std::unique_ptr<Elf_Phdr>(phdr));
        off += elfHeader.e_phentsize;
    }

    for (off = elfHeader.e_shoff, i = 0; i < elfHeader.e_shnum; i++) {
        Elf_Shdr *shdr = new Elf_Shdr();
        io->readObj(off, shdr);
        sectionHeaders.push_back(std::unique_ptr<Elf_Shdr>(shdr));
        off += elfHeader.e_shentsize;
    }

    if (elfHeader.e_shstrndx != SHN_UNDEF) {
        auto sshdr = sectionHeaders[elfHeader.e_shstrndx];
        for (auto &h : sectionHeaders)
            namedSection[io->readString(sshdr->sh_offset + h->sh_name)] = h.get();
        auto tab = namedSection[".hash"];
        if (tab)
            hash.reset(new ElfSymHash(this, tab));
    } else {
        hash = 0;
    }
}

std::pair<const Elf_Sym, const std::string>
SymbolIterator::operator *()
{
        Elf_Sym sym;
        io->readObj(off, &sym);
        std::string name = io->readString(sym.st_name + stroff);
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
ElfObject::findSymbolByAddress(Elf_Addr addr, int type, Elf_Sym &sym, std::string &name)
{

    /* Try to find symbols in these sections */
    static const char *sectionNames[] = {
        ".dynsym", ".symtab", 0
    };

    bool exact = false;
    Elf_Addr lowest = 0;
    for (size_t i = 0; sectionNames[i] && !exact; i++) {
        const Elf_Shdr *symSection = namedSection[sectionNames[i]];
        if (symSection == 0)
            continue;

        SymbolSection syms(this, symSection);
        for (auto syminfo : syms) {
            auto &candidate = syminfo.first;
            if (candidate.st_shndx >= sectionHeaders.size())
                continue;
            Elf_Shdr *shdr = sectionHeaders[candidate.st_shndx].get();
            if (!(shdr->sh_flags & SHF_ALLOC))
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

SymbolSection
ElfObject::getSymbols(size_t section)
{
    return SymbolSection(this, namedSection[".dynsym"]);
}

bool
ElfObject::linearSymSearch(const Elf_Shdr *hdr, std::string name, Elf_Sym &sym)
{
    SymbolSection sec(this, hdr);
    for (auto info : sec) {
        if (name == info.second) {
            sym = info.first;
            return true;
        }
    }
    return false;
}

ElfSymHash::ElfSymHash(ElfObject *obj_, const Elf_Shdr *hash_)
    : obj(obj_)
    , hash(hash_)
{
    syms = obj->getSection(hash->sh_link);

    // read the hash table into local memory.
    size_t words = hash->sh_size / sizeof (Elf_Word);
    data.resize(words);
    obj->io->readObj(hash->sh_offset, &data[0], words);
    nbucket = data[0];
    nchain = data[1];
    buckets = &data[0] + 2;
    chains = buckets + nbucket;
    strings = obj->sectionHeaders[syms->sh_link]->sh_offset;
}

bool
ElfSymHash::findSymbol(Elf_Sym &sym, std::string &name)
{
    uint32_t bucket = elf_hash(name) % nbucket;
    for (Elf_Word i = buckets[bucket]; i != STN_UNDEF; i = chains[i]) {
        Elf_Sym candidate;
        obj->io->readObj(syms->sh_offset + i * sizeof candidate, &candidate);
        std::string candidateName = obj->io->readString(strings + candidate.st_name);
        if (candidateName == name) {
            sym = candidate;
            name = candidateName;
            return true;
        }
    }
    return false;
}

/*
 * Locate a named symbol in an ELF image.
 */
bool
ElfObject::findSymbolByName(std::string name, Elf_Sym &sym)
{
    if (hash && hash->findSymbol(sym, name))
        return true;
    const Elf_Shdr *syms = namedSection[".dynsym"];
    if (syms && linearSymSearch(syms, name, sym))
        return true;
    syms = namedSection[".symtab"];
    if (syms && linearSymSearch(syms, name, sym))
        return true;
    return false;
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
    psinfo = data;

    if (!strcmp(name, "FreeBSD") && type == NT_PRPSINFO &&
        psinfo->pr_version == PRPSINFO_VERSION) {
        *exename = psinfo->pr_fname;
        return NOTE_DONE;
    }
    return NOTE_CONTIN;
}

#endif

std::string
ElfObject::getImageFromCore()
{
#ifdef __FreeBSD__
    return elfGetNotes(obj, elfImageNote, name);
#endif
#ifdef __linux__
    return "";
#endif
}

/*
 * Attempt to find a prefix to an executable ABI's "emulation tree"
 */
std::string
ElfObject::getABIPrefix()
{
#ifdef __FreeBSD__
    int i;
    static struct {
        int brand;
        const char *oldBrand;
        const char *interpreter;
        const char *prefix;
    } knownABIs[] = {
        { ELFOSABI_FREEBSD,
            "FreeBSD", "/usr/libexec/ld-elf.so.1", 0},
        { ELFOSABI_LINUX,
            "Linux", "/lib/ld-linux.so.1", "/compat/linux"},
        { ELFOSABI_LINUX,
            "Linux", "/lib/ld-linux.so.2", "/compat/linux"},
        { -1,0,0,0 }
    };

    /* Trust EI_OSABI, or the 3.x brand string first */
    for (i = 0; knownABIs[i].brand != -1; i++) {
        if (knownABIs[i].brand == obj->elfHeader->e_ident[EI_OSABI] ||
            strcmp(knownABIs[i].oldBrand,
            (const char *)obj->elfHeader->e_ident + OLD_EI_BRAND) == 0)
            return knownABIs[i].prefix;
    }
    /* ... Then the interpreter */
    if (obj->interpreterName) {
        for (i = 0; knownABIs[i].brand != -1; i++) {
            if (strcmp(knownABIs[i].interpreter,
                obj->interpreterName) == 0)
                return knownABIs[i].prefix;
        }
    }
#endif
    /* No prefix */
    return "";
}

ElfObject::~ElfObject()
{
}

/*
 * Culled from System V Application Binary Interface
 */
static uint32_t
elf_hash(std::string name)
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
