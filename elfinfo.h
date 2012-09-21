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
 * Utility interface for accessing ELF images.
 */

#ifndef elfinfo_h_guard
#define elfinfo_h_guard

#include <tuple>
#include <string>
#include <list>
#include <vector>
#include <elf.h>
extern "C" {
#include <thread_db.h>
}
#include <elf.h>
#include "reader.h"

/*
 * FreeBSD defines all elf types with a common header, defining the
 * 64 and 32 bit versions through a common body, giving us platform
 * independent names for each one. We work backwards on Linux to
 * provide the same handy naming.
 */

#define ELF_WORDSIZE ((ELF_BITS)/8)

#ifndef __FreeBSD__

#define ElfTypeForBits(type, bits, uscore) typedef Elf##bits##uscore##type Elf##uscore##type ;
#define ElfType2(type, bits) ElfTypeForBits(type, bits, _)
#define ElfType(type) ElfType2(type, ELF_BITS)

typedef Elf32_Nhdr Elf32_Note;
typedef Elf64_Nhdr Elf64_Note;

ElfType(Addr)
ElfType(Ehdr)
ElfType(Phdr)
ElfType(Shdr)
ElfType(Sym)
ElfType(Dyn)
ElfType(Word)
ElfType(Note)
ElfType(auxv_t)
ElfType(Off)

#if ELF_BITS==64
#define ELF_ST_TYPE ELF64_ST_TYPE
#define IS_ELF(a) 1
#endif

#if ELF_BITS==32
#define ELF_ST_TYPE ELF32_ST_TYPE
#define IS_ELF(a) 1
#endif

static inline size_t roundup2(size_t val, size_t align)
{
    return val + (align - (val % align)) % align;
}

#endif

struct DwarfInfo;
class ElfSymHash;

#define MEMBUF (1024 * 64)

enum NoteIter {
    NOTE_CONTIN,
    NOTE_ERROR,
    NOTE_DONE
};

struct ElfObject {
    Elf_Off base; /* For loaded objects */
    Elf_Off load;
    CacheReader io;
    size_t fileSize;
    Elf_Ehdr elfHeader;
    std::vector<Elf_Phdr *> programHeaders;
    std::vector<Elf_Shdr *> sectionHeaders;
    const Elf_Phdr *dynamic;
    off_t sectionStrings;
    std::string interpreterName;
    DwarfInfo *dwarf;
    bool linearSymSearch(const Elf_Shdr *hdr, std::string name, Elf_Sym &);
    void init(FILE *);
    ElfSymHash *hash;
public:
    Elf_Shdr *findSectionByName(std::string name);
    bool findSymbolByAddress(Elf_Addr addr, int type, Elf_Sym &, std::string &);
    bool findSymbolByName(std::string name, Elf_Sym &sym);
    std::string getABIPrefix();
    ElfObject(Reader &);
    ~ElfObject();
    inline Elf_Addr addrProc2Obj(Elf_Addr va) const { return va - load + base; }
    inline Elf_Addr addrObj2Proc(Elf_Addr va) const { return va - base + load; }
    Elf_Shdr *getSection(size_t idx) const {
        if (idx >= sectionHeaders.size())
            throw 999;
        return sectionHeaders[idx];
    }
    template <typename Callable> void getNotes(const Callable &callback) const;
    std::string getImageFromCore();
    const Elf_Phdr *findHeaderForAddress(Elf_Addr pa) const;
};

// Helpful for iterating over symbol sections.
struct SymbolIterator {
    Reader &io;
    off_t off;
    off_t stroff;
    SymbolIterator(Reader &io_, off_t off_, off_t stroff_) : io(io_), off(off_), stroff(stroff_) {}
    bool operator != (const SymbolIterator &rhs) { return rhs.off != off; }
    SymbolIterator &operator++ () { off += sizeof (Elf_Sym); return *this; }
    std::pair<const Elf_Sym, const std::string> operator *();
};

struct SymbolSection {
    Reader &io;
    const Elf_Shdr *section;
    off_t stroff;
    SymbolIterator begin() { return SymbolIterator(io, section ?  section->sh_offset : 0, stroff); }
    SymbolIterator end() { return SymbolIterator(io, section ?  section->sh_offset + section->sh_size : 0, stroff); }
    SymbolSection(ElfObject *obj, const Elf_Shdr *section_)
        : io(obj->io)
        , section(section_)
        , stroff(obj->sectionHeaders[section->sh_link]->sh_offset)
    {}
};

class ElfSymHash {
    ElfObject *obj;
    const Elf_Shdr *hash;
    const Elf_Shdr *syms;
    off_t strings;
    Elf_Word nbucket;
    Elf_Word nchain;
    const Elf_Word *buckets;
    const Elf_Word *chains;
    const Elf_Word *data;
public:
    ElfSymHash(ElfObject *object, Elf_Shdr *hash);
    bool findSymbol(Elf_Sym &sym, std::string &name);
};

void hexdump(FILE *f, int indent, const unsigned char *p, int len);
const char *pad(size_t size);
typedef struct user_regs_struct CoreRegisters;

std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr &, const Elf_Sym &> &t);
std::ostream& operator<< (std::ostream &os, const std::pair<const ElfObject *, const Elf_Shdr &> &p);
std::ostream& operator<< (std::ostream &os, const Elf_Phdr &h);
std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr &, const Elf_Sym &> &t);
std::ostream& operator<< (std::ostream &os, const Elf_Dyn &d);
std::ostream& operator<< (std::ostream &os, const ElfObject &obj);

template <typename Callable> void
ElfObject::getNotes(const Callable &callback) const
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
                NoteIter iter = callback(name, note.n_type, data, note.n_descsz);
                delete[] data;
                delete[] name;
                switch (iter) {
                case NOTE_DONE:
                case NOTE_ERROR:
                    return;
                case NOTE_CONTIN:
                    break;
                }
            }
        }
    }
}


#endif /* Guard. */
