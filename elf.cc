/*
 * Copyright (c) 2002 Peter Edwards
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Implementation of utlities for accessing ELF images.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/procfs.h>

#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "elfinfo.h"
#include "dwarf.h"

#include <iostream>

static uint32_t elf_hash(std::string);

/*
 * Parse out an ELF file into an ElfObject structure.
 */

std::string
ElfObject::readString(off_t offset) const
{
    char c;
    std::string res;
    for (;;) {
        io.readObj(offset++, &c);
        if (c == 0)
            break;
        res += c;
    }
    return res;
}

const Elf_Phdr *
ElfObject::findHeaderForAddress(Elf_Addr pa) const
{
    Elf_Addr va = addrProc2Obj(pa);
    for (auto hdr : programHeaders)
        if (hdr->p_vaddr <= va && hdr->p_vaddr + hdr->p_filesz > va && hdr->p_type == PT_LOAD)
            return hdr;
    return 0;
}


FileReader::FileReader(std::string name_, FILE *file_)
    : name(name_)
    , file(file_)
{
    if (file == 0 && (file = fopen(name.c_str(), "r")) == 0)
        throw 999;
}

ElfObject::ElfObject(Reader &io_)
    : io(io_)
    , mem(&firstChunk)

{
    Elf_Ehdr *eHdr;

    int i;
    size_t off;

    firstChunk.size = MEMBUF;
    firstChunk.used = 0;
    io.readObj(0, &elfHeader);

    /* Validate the ELF header */
    if (!IS_ELF(elfHeader) || elfHeader.e_ident[EI_VERSION] != EV_CURRENT)
        throw "not an ELF image";

    eHdr = &elfHeader;

    for (off = eHdr->e_phoff, i = 0; i < eHdr->e_phnum; i++) {
        Elf_Phdr *phdr = new Elf_Phdr();
        io.readObj(off, phdr);
        switch (phdr->p_type) {
        case PT_INTERP:
                interpreterName = readString(phdr->p_offset);
                break;
        case PT_DYNAMIC:
                dynamic = phdr;
                break;
        }
        programHeaders.push_back(phdr);
        off += eHdr->e_phentsize;
    }
    for (off = eHdr->e_shoff, i = 0; i < eHdr->e_shnum; i++) {
        Elf_Shdr *shdr = new Elf_Shdr();
        io.readObj(off, shdr);
        sectionHeaders.push_back(shdr);
        off += eHdr->e_shentsize;
    }

    if (eHdr->e_shstrndx != SHN_UNDEF) {
        Elf_Shdr *sshdr = sectionHeaders[eHdr->e_shstrndx];
        sectionStrings = sshdr->sh_offset;
    } else {
        sectionStrings = 0;
    }
    Elf_Shdr *tab = findSectionByName(".hash");
    hash = tab ? new ElfSymHash(this, tab) : 0;
}

/*
 * Given an Elf object, find a particular section.
 */
Elf_Shdr *
ElfObject::findSectionByName(std::string name)
{
    for (size_t i = 0; i < elfHeader.e_shnum; ++i) {
        Elf_Shdr *hdr = sectionHeaders[i];
        if (name == readString(sectionStrings + hdr->sh_name)) {
            return hdr;
        }
    }
    return 0;
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
        Elf_Shdr *symSection = findSectionByName(sectionNames[i]);
        if (symSection == 0)
            continue;
        /*
         * Found the section in question: get the associated
         * string section's data, and a pointer to the start
         * and end of the table
         */
        off_t symoff = symSection->sh_offset;
        off_t symend = symoff + symSection->sh_size;
        off_t stringoff = sectionHeaders[symSection->sh_link]->sh_offset;

        Elf_Sym candidate;
        for (; symoff < symend && !exact; symoff += sizeof sym) {
            io.readObj(symoff, &candidate);
            if (candidate.st_shndx >= sectionHeaders.size())
                continue;
            Elf_Shdr *shdr = sectionHeaders[candidate.st_shndx];
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
                    name = readString(candidate.st_name + stringoff);
                    return true;
                }
            } else if (lowest < candidate.st_value) {
                sym = candidate;
                name = readString(candidate.st_name + stringoff);
                lowest = candidate.st_value;
            }
        }
    }
    return lowest != 0;
}

bool
ElfObject::linearSymSearch(const Elf_Shdr *hdr, std::string name, Elf_Sym &sym)
{
    off_t symStrings = sectionHeaders[hdr->sh_link]->sh_offset;
    off_t off = hdr->sh_offset;
    off_t end = off + hdr->sh_size;

    for (; off < end; off += sizeof sym) {
        Elf_Sym candidate;
        io.readObj(off, &candidate);
        if (name == readString(symStrings + candidate.st_name)) {
            sym = candidate;
            return true;
        }
    }
    return false;
}

ElfSymHash::ElfSymHash(ElfObject *obj_, Elf_Shdr *hash_)
    : obj(obj_)
    , hash(hash_)
{
    syms = obj->getSection(hash->sh_link);

    // read the hash table into local memory.
    size_t words = hash->sh_size / sizeof (Elf_Word);

    data = new Elf_Word[words];
    obj->io.readObj(hash->sh_offset, data, words);
    nbucket = data[0];
    nchain = data[1];
    buckets = data + 2;
    chains = buckets + nbucket;
    strings = obj->sectionHeaders[syms->sh_link]->sh_offset;
}

bool
ElfSymHash::findSymbol(Elf_Sym &sym, std::string &name)
{
    uint32_t bucket = elf_hash(name) % nbucket;
    for (Elf_Word i = buckets[bucket]; i != STN_UNDEF; i = chains[i]) {
        Elf_Sym candidate;
        obj->io.readObj(syms->sh_offset + i * sizeof candidate, &candidate);
        std::string candidateName = obj->readString(strings + candidate.st_name);
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
    Elf_Shdr *syms = findSectionByName(".dynsym");
    if (syms && linearSymSearch(syms, name, sym))
        return true;
    syms = findSectionByName(".symtab");
    if (syms && linearSymSearch(syms, name, sym))
        return true;
    return false;
}

/*
 * Get the data and length from a specific "note" in the ELF file
 */
int
ElfObject::getNotes(enum NoteIter (*callback)(void *cookie, const char *name, u_int32_t type, const void *datap, size_t len), void *cookie) const
{
    for (auto phdr : programHeaders) {
        if (phdr->p_type == PT_NOTE) {
            Elf_Note note;
            off_t off = phdr->p_offset;
            off_t e = off + phdr->p_filesz;
            while (off < e) {
                io.readObj(off, &note);
                off += sizeof note;
                char *name = new char[note.n_namesz + 1];
                io.readObj(off, name, note.n_namesz);
                name[note.n_namesz] = 0;
                off += note.n_namesz;
                off = roundup2(off, 4);
                char *data = new char[note.n_descsz];
                io.readObj(off, data, note.n_descsz);
                off += note.n_descsz;
                off = roundup2(off, 4);
                NoteIter iter = callback(cookie, name, note.n_type, data, note.n_descsz);
                delete[] data;
                delete[] name;
                switch (iter) {
                case NOTE_DONE:
                    return 0;
                case NOTE_CONTIN:
                    break;
                case NOTE_ERROR:
                    return -1;
                }
            }
        }
    }
    return -2;
}

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
    struct ElfMemChunk *next, *chunk;
    for (chunk = mem; chunk != &firstChunk; chunk = next) {
        next = chunk->next;
        free(chunk);
    }
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

#ifdef NOTYET

static const char *
auxTypeName(int t)
{
#define T(name) case name: return #name;
    switch (t) {
         T(AT_IGNORE)
         T(AT_EXECFD)
         T(AT_PHDR)
         T(AT_PHENT)
         T(AT_PHNUM)
         T(AT_PAGESZ)
         T(AT_BASE)
         T(AT_FLAGS)
         T(AT_ENTRY)
         T(AT_NOTELF)
         T(AT_UID)
         T(AT_EUID)
         T(AT_GID)
         T(AT_EGID)
         T(AT_CLKTCK)
         T(AT_SYSINFO)
         T(AT_SYSINFO_EHDR)
         default: return "unknown";
    }
#undef T
}

static enum NoteIter
noteprinter(void *cookie, const char *name, u_int32_t type, const void *datap, size_t len)
{

    fprintf(cookie, "note %s (type %d){ \n", name, type);
    hexdump(cookie, 4, datap, len);
    fprintf(cookie, "}\n");
    switch (type) {
        case NT_PRSTATUS: {
            const prstatus_t *prstatus = (const prstatus_t *)datap;
            fprintf(cookie, "prstatus: pid: %d, signal: %d\n", prstatus->pr_pid, prstatus->pr_cursig);
        }
        break;
        case NT_AUXV: {
            const Elf_auxv_t *aux = datap;
            const Elf_auxv_t *eaux = aux + len / sizeof *aux;

            fprintf(cookie, "auxv:\n");
            while (aux < eaux) {
                fprintf(cookie, "\ttype=%s/%d, val=%d/0x%x\n",
                        auxTypeName(aux->a_type),
                        aux->a_type,
                        aux->a_un.a_val,
                        aux->a_un.a_val);
                aux++;
            }

        }
        break;
    }
    return NOTE_CONTIN; 

}
#endif

/*
 * Helps for pretty-printing
 */
const char *
pad(size_t size)
{

    static const char padding[] =
        "                                        "
        "                                        "
        "                                        "
        "                                        "
        "                                        ";

    if (size > sizeof padding - 1)
        size = sizeof padding - 1;
    return (padding + sizeof padding - 1 - size);
}

void
hexdump(FILE *f, int indent, const unsigned char *p, int len)
{
    const unsigned char *cp = (const unsigned char *)p;
    char hex[16 * 3 + 1], *hp, ascii[16 + 1], *ap;
    int i, c;

    if (!len)
        return;
    while (len) {
        hp = hex;
        ap = ascii;
        for (i = 0; len && i < 16; i++) {
            c = *cp++;
            len--;
            hp += sprintf(hp, "%02x ", c);
            *ap++ = c < 127 && c >= 32 ? c : '.';
        }
        *ap = 0;
        fprintf(f, "%s%-48s |%-16s|\n", pad(indent), hex, ascii);
    }
}

void *
elfAlloc(struct ElfObject *obj, size_t size)
{

    size = (size + ELF_WORDSIZE - 1);
    size -= size % ELF_WORDSIZE;
    char *p;
    size_t chunksize;
    struct ElfMemChunk *chunk;
    for (chunk = obj->mem; chunk; chunk = chunk->next) {
        if (chunk->size - chunk->used >= size) {
            p = chunk->data + chunk->used;
            chunk->used += size;
            return p;
        }
    }
    /* No memory in any existing chunk, create a new one. */
    if (size > MEMBUF / 2) {
        chunksize = MEMBUF / 2 + size;
    } else {
        chunksize = MEMBUF;
    }
    chunk = (ElfMemChunk *)malloc(sizeof *chunk + chunksize - sizeof chunk->data);
    chunk->next = obj->mem;
    chunk->size = chunksize;
    chunk->used = size;
    obj->mem = chunk;
    return chunk->data;
}

char *
elfStrdup(struct ElfObject *elf, const char *old)
{
    char *newstr = (char *)elfAlloc(elf, strlen(old) + 1);
    strcpy(newstr, old);
    return newstr;
}
