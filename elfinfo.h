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
#include <string>
#include <list>
#include <vector>
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

struct ElfMemChunk {
    struct ElfMemChunk *next;
    size_t size;
    size_t used;
    char data[1];
};

#define MEMBUF (1024 * 64)

enum NoteIter {
	NOTE_CONTIN,
	NOTE_ERROR,
	NOTE_DONE
};

struct ElfObject {
    Elf_Addr base; /* For loaded objects */
    Elf_Addr load;
    Reader &io;
    size_t fileSize;
    Elf_Ehdr elfHeader;
    std::vector<Elf_Phdr *> programHeaders;
    std::vector<Elf_Shdr *> sectionHeaders;
    const Elf_Phdr *dynamic;
    off_t sectionStrings;
    std::string interpreterName;
    DwarfInfo *dwarf;
    struct ElfMemChunk firstChunk;
    char buf[MEMBUF];
    struct ElfMemChunk *mem;
    std::string readString(off_t offset) const;
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
    int	getNotes(enum NoteIter (*callback)(void *cookie, const char *name, uint32_t type, const void *datap, size_t len), void *cookie) const;
    std::string getImageFromCore();
    const Elf_Phdr *findHeaderForAddress(Elf_Addr pa) const;
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

struct stab {
	unsigned long n_strx;
	unsigned char n_type;
	unsigned char n_other;
	unsigned short n_desc;
	unsigned long n_value;
};

enum StabType {
	N_UNDF = 0x0, 
	N_ABS = 0x2,
	N_ABS_EXT = 0x3, 
	N_TEXT = 0x4, 
	N_TEXT_EXT = 0x5, 
	N_DATA = 0x6, 
	N_DATA_EXT = 0x7, 
	N_BSS = 0x8, 
	N_BSS_EXT = 0x9, 
	N_FN_SEQ = 0x0c, 
	N_INDR = 0x0a, 
	N_COMM = 0x12, 
	N_SETA = 0x14,
	N_SETA_EXT = 0x15, 
	N_SETT = 0x16,
	N_SETT_EXT = 0x17, 
	N_SETD = 0x18,
	N_SETD_EXT = 0x19, 
	N_SETB = 0x1a, 
	N_SETB_EXT = 0x1b, 
	N_SETV = 0x1c,
	N_SETV_EXT = 0x1d, 
	N_WARNING = 0x1e, 
	N_FN = 0x1f, 
	N_GSYM = 0x20, 
	N_FNAME = 0x22, 
	N_FUN = 0x24, 
	N_STSYM = 0x26, 
	N_LCSYM = 0x28, 
	N_MAIN = 0x2a, 
	n_ROSYM = 0x2c, 
	N_PC = 0x30, 
	N_NSYMS = 0x32, 
	N_NOMAP = 0x34, 
	N_OBJ = 0x38, 
	N_OPT = 0x3c, 
	N_RSYM = 0x40, 
	N_M2C = 0x42, 
	N_SLINE = 0x44, 
	N_DSLINE = 0x46, 
	N_BSLINE = 0x48, 
	N_DEFD = 0x4a, 
	N_FLINE = 0x4c, 
	N_EHDECL = 0x50, 
	N_CATCH = 0x54, 
	N_SSYM = 0x60, 
	N_ENDM = 0x62, 
	N_SO = 0x64, 
	N_LSYM = 0x80, 
	N_BINCL = 0x82, 
	N_SOL = 0x84, 
	N_PSYM = 0xa0, 
	N_EINCL = 0xa2, 
	N_ENTRY = 0xa4, 
	N_LBRAC = 0xc0, 
	N_EXCL = 0xc2, 
	N_SCOPE = 0xc4, 
	N_RBRAC = 0xe0, 
	N_BCOMM = 0xe2, 
	N_ECOMM = 0xe4, 
	N_ECOML = 0xe8, 
	N_WITH = 0xea, 
	N_NBTEXT = 0xf0, 
	N_NBDATA = 0xf2, 
	N_NBBSS = 0xf4, 
	N_NBSTS = 0xf6, 
	N_NBLCS = 0xf8
};

struct MappedPage {
	unsigned char *data;
	Elf_Addr address; /* Valid only if data != NULL */
	int lastAccess;
};


int elfGetImageFromCore(struct ElfObject *obj, const char **name);

void elfDumpSymbol(FILE *f, const Elf_Sym *sym, const char *strings, int indent);
void elfDumpDynamic(FILE *f, const Elf_Dyn *dyn, int indent);
void elfDumpObject(FILE *f, struct ElfObject *obj, int snap, int indent);
void elfDumpSection(FILE * f, struct ElfObject * obj, const Elf_Shdr * hdr, size_t snap, int indent);
void elfDumpProgramSegment(FILE *f, struct ElfObject *obj, const Elf_Phdr *hdr, int indent);

void hexdump(FILE *f, int indent, const unsigned char *p, int len);
const char *pad(size_t size);
typedef struct user_regs_struct CoreRegisters;

std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr &, const Elf_Sym &> &t);
std::ostream& operator<< (std::ostream &os, const std::pair<const ElfObject *, const Elf_Shdr &> &p);
std::ostream& operator<< (std::ostream &os, const Elf_Phdr &h);
std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr &, const Elf_Sym &> &t);
std::ostream& operator<< (std::ostream &os, const Elf_Dyn &d);
std::ostream& operator<< (std::ostream &os, const ElfObject &obj);

#endif /* Guard. */
