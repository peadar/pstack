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
#include <sys/queue.h>
#include <proc_service.h>
#include <thread_db.h>
typedef struct ps_prochandle Process;

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

struct tagDwarfInfo;
struct ElfMemChunk {
    struct ElfMemChunk *next;
    size_t size;
    size_t used;
    char data[1];
};
#define MEMBUF (1024 * 64)

struct ElfObject {
	struct ElfObject *next;
	Elf_Addr	 base; /* For loaded objects */
	Elf_Addr	 load;
        FILE            *file;
	char		*fileName;
	size_t		 fileSize;
	Elf_Ehdr	 elfHeader;
	Elf_Phdr        *programHeaders;
	Elf_Shdr        *sectionHeaders;
	const char     **sectionContents;
	const Elf_Phdr  *dynamic;
	const char	*sectionStrings;
	const char	*interpreterName;
        struct tagDwarfInfo *dwarf;

        struct ElfMemChunk firstChunk;
        char buf[MEMBUF];
        struct ElfMemChunk *mem;
};

struct stab {
	unsigned long n_strx;
	unsigned char n_type;
	unsigned char n_other;
	unsigned short n_desc;
	unsigned long n_value;
};

enum NoteIter {
	NOTE_CONTIN,
	NOTE_ERROR,
	NOTE_DONE
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

struct StackFrame {
	STAILQ_ENTRY(StackFrame) link;
	Elf_Addr	ip;
	Elf_Addr	bp;
	int		argCount;
	Elf_Word	args[1];
        const char     *unwindBy;
};

STAILQ_HEAD(StackFrameList, StackFrame);

struct MappedPage {
	unsigned char *data;
	Elf_Addr address; /* Valid only if data != NULL */
	int lastAccess;
};


#define PAGECACHE_SIZE 4
struct PageCache {
	struct MappedPage pages[PAGECACHE_SIZE];
	int		accessGeneration;
};

struct Thread {
	int running;
	struct Thread		*next;
	struct StackFrameList	stack;
	thread_t threadId;
	lwpid_t lwpid;
};

struct ps_prochandle {
	td_thragent_t	*agent;
	pid_t		 pid;
	int		 objectCount;
	struct ElfObject *objectList;
	struct ElfObject *execImage;
	struct ElfObject *coreImage;
	struct Thread	*threadList;
	const char	*abiPrefix;
	struct PageCache pageCache;
        unsigned char *vdso;
};

int	procFindObject(Process *p, Elf_Addr addr, struct ElfObject **objp);

int	elfFindSectionByName(struct ElfObject *obj,
			const char *name, const Elf_Shdr **sectionp);
int	elfFindSymbolByAddress(struct ElfObject *obj,
			Elf_Addr addr, int type,
			const Elf_Sym **symp, const char **namep);
int	elfLinearSymSearch(struct ElfObject *o,
			const Elf_Shdr *hdr,
			const char *name, const Elf_Sym **symp);
int	elfFindSymbolByName(struct ElfObject *o,
			const char *name, const Elf_Sym **symp);
int	elfLoadObject(const char *fileName, struct ElfObject **objp);
int     elfLoadObjectFromData(FILE *data, size_t size, struct ElfObject **objp);
int	elfGetNotes(struct ElfObject *obj, enum NoteIter
		(*callback)(void *cookie, const char *name, uint32_t type,
		const void *datap, size_t len), void *cookie);
int	elfGetImageFromCore(struct ElfObject *obj, const char **name);
int	elfUnloadObject(struct ElfObject *obj);
const char *elfGetAbiPrefix(struct ElfObject *o);
void	elfDumpSymbol(FILE *f, const Elf_Sym *sym,
			const char *strings, int indent);
void	elfDumpDynamic(FILE *f, const Elf_Dyn *dyn, int indent);
void	elfDumpObject(FILE *f, struct ElfObject *obj, int snap, int indent);
void	elfDumpSection(FILE * f, struct ElfObject * obj,
			const Elf_Shdr * hdr, size_t snap, int indent);
void	elfDumpProgramSegment(FILE *f, struct ElfObject *obj,
			const Elf_Phdr *hdr, int indent);
void	hexdump(FILE *f, int indent, const unsigned char *p, int len);
const char *	pad(size_t size);
void   *elfAlloc(struct ElfObject *, size_t);
char   *elfStrdup(struct ElfObject *, const char *);
static inline Elf_Addr elfAddrProc2Obj(const struct ElfObject *obj, Elf_Addr va) { return va - obj->load + obj->base; }
static inline Elf_Addr elfAddrObj2Proc(const struct ElfObject *obj, Elf_Addr va) { return va - obj->base + obj->load; }
typedef struct user_regs_struct CoreRegisters;

size_t	procReadMem(Process *p, void *ptr, Elf_Addr remoteAddr, size_t size);

#endif /* Guard. */
