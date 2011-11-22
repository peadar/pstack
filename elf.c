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

static unsigned long	elf_hash(const char *name);

/*
 * Parse out an ELF file into an ElfObject structure.
 */

#define READOBJ(file, offset, object) \
    (fseek(file, offset, SEEK_SET) == 0 && fread(&object, sizeof object, 1, file) == 1)

#define READDAT(file, offset, size, data) \
    (fseek(file, offset, SEEK_SET) == 0 && fread(data, 1, size, file) == 1)



const char *
readString(struct ElfObject *obj, size_t offset)
{
    int c, count;
    char *rv;
    if (fseek(obj->file, offset, SEEK_SET) == 0)
        return 0;
    do {
        c = fgetc(obj->file);
        count++;
    } while (c != 0 && c != -1);
    rv = elfAlloc(obj, count);
    if (fseek(obj->file, offset, SEEK_SET))
        return 0;
    if (fread(rv, 1, count, obj->file) != count)
        return 0;
    return rv;
}



int
elfLoadObjectFromData(FILE *content, size_t size, struct ElfObject **objp)
{
    struct ElfObject *obj;
    Elf_Ehdr *eHdr;
    Elf_Shdr *sHdrs;
    Elf_Phdr *pHdrs;
    int i;
    size_t off;

    obj = calloc(1, sizeof(*obj));
    obj->mem = &obj->firstChunk;
    obj->firstChunk.size = MEMBUF;
    obj->firstChunk.used = 0;

    obj->fileSize = size;
    obj->file = content;
    if (!READOBJ(content, 0, obj->elfHeader))
        return -1;

    /* Validate the ELF header */
    if (!IS_ELF(obj->elfHeader) || obj->elfHeader.e_ident[EI_VERSION] != EV_CURRENT) {
            warnx("not an ELF image");
            free(obj);
            return (-1);
    }
    eHdr = &obj->elfHeader;
    pHdrs = obj->programHeaders = elfAlloc(obj, sizeof(Elf_Phdr) * eHdr->e_phnum);

    for (off = eHdr->e_phoff, i = 0; i < eHdr->e_phnum; i++) {
        if (!READOBJ(content, off, pHdrs[i])) 
            return -1;
        switch (pHdrs[i].p_type) {
        case PT_INTERP:
                obj->interpreterName = readString(obj, pHdrs[i].p_offset);
                break;
        case PT_DYNAMIC:
                obj->dynamic = pHdrs + i;
                break;
        }
        off += eHdr->e_phentsize;
    }
    obj->sectionHeaders = sHdrs = elfAlloc(obj, sizeof(Elf_Shdr *) * eHdr->e_shnum);
    obj->sectionContents = elfAlloc(obj, sizeof(char *) * eHdr->e_shnum);
    for (off = eHdr->e_shoff, i = 0; i < eHdr->e_shnum; i++) {
        if (!READOBJ(content, off, sHdrs[i]))
            return -1;
        off += eHdr->e_shentsize;
        obj->sectionContents[i] = 0;
    }

    if (eHdr->e_shstrndx != SHN_UNDEF) {
        Elf_Shdr *sshdr = &sHdrs[eHdr->e_shstrndx];
        char *p;
        obj->sectionStrings = p = elfAlloc(obj, sshdr->sh_size);
        READDAT(content, sshdr->sh_offset, sshdr->sh_size, p);
    } else {
        obj->sectionStrings = 0;
    }
    obj->fileName = 0;
    *objp = obj;
    return (0);
}

const char *getSectionContent(struct ElfObject *obj, size_t section)
{
    if (section == SHN_UNDEF)
        return 0;
    if (obj->sectionContents[section] == 0) {
        Elf_Shdr *sh = &obj->sectionHeaders[section];
        char *p;
        obj->sectionContents[section] = p = elfAlloc(obj, sh->sh_size);
        READDAT(obj-file, sh->sh_offset, sh->sh_size, p);
    }
    return obj->sectionContents[section];
}

int
elfLoadObject(const char *fileName, struct ElfObject **objp)
{
    unsigned char *data;
    FILE *file;
    int rc;
    struct stat sb;

    if ((file = fopen(fileName, "r")) == 0) {
        warn("unable to open executable '%s'", fileName);
        return (-1);
    }
    rc = elfLoadObjectFromData(file, sb.st_size, objp);
    if (rc == 0) {
        (*objp)->fileName = elfStrdup((*objp), fileName);
    } else {
        munmap(data, sb.st_size);
    }
    return rc;
}



/*
 * Given an Elf object, find a particular section.
 */
int
elfFindSectionByName(struct ElfObject *obj, const char *name,
			const Elf_Shdr **shdrp)
{
    int i;

    for (i = 0; i < obj->elfHeader.e_shnum; i++)
        if (strcmp(obj->sectionHeaders[i].sh_name + obj->sectionStrings, name) == 0) {
            *shdrp = &obj->sectionHeaders[i];
            return (0);
        }
    return (-1);
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
int
elfFindSymbolByAddress(struct ElfObject *obj, Elf_Addr addr,
			int type, const Elf_Sym **symp, const char **namep)
{
    const Elf_Shdr *symSection, *shdrs;
    const Elf_Sym *sym, *endSym;
    const char *symStrings;
    const char *sectionNames[] = { ".dynsym", ".symtab", 0 };
    int i, exact = 0;

    /* Try to find symbols in these sections */
    *symp = 0;
    shdrs = obj->sectionHeaders;
    for (i = 0; sectionNames[i] && !exact; i++) {
        if (elfFindSectionByName(obj, sectionNames[i],
            &symSection) != 0)
                continue;
        /*
         * Found the section in question: get the associated
         * string section's data, and a pointer to the start
         * and end of the table
         */
        symStrings = getSectionContent(obj, shdrs[symSection->sh_link]);
        sym = (const Elf_Sym *)getSectionContent(obj, symSection);

        endSym = (const Elf_Sym *)(obj->fileData + symSection->sh_offset + symSection->sh_size);

        for (; sym < endSym; sym++) {
            if ((type == STT_NOTYPE || ELF_ST_TYPE(sym->st_info) == type) && sym->st_value <= addr && (shdrs[sym->st_shndx].sh_flags & SHF_ALLOC)) {
                if (sym->st_size) {
                    if (sym->st_size + sym->st_value > addr) {
                        *symp = sym;
                        *namep = symStrings + sym->st_name;
                        exact = 1;
                    }
                } else {
                    if ((*symp) == 0 || (*symp)->st_value < sym->st_value) {
                        *symp = sym;
                        *namep = symStrings +
                        sym->st_name;
                    }
                }
            }
        }
    }
    return (*symp ? 0 : -1);
}

int
elfLinearSymSearch(struct ElfObject *o, const Elf_Shdr *hdr,
			const char *name, const Elf_Sym **symp)
{
    const char *symStrings;
    const Elf_Sym *sym, *endSym;

    symStrings = (const char *)o->fileData +
        o->sectionHeaders[hdr->sh_link]->sh_offset;

    sym = (const Elf_Sym *)(o->fileData + hdr->sh_offset);
    endSym = (const Elf_Sym *)
        (o->fileData + hdr->sh_offset + hdr->sh_size);
    for (; sym < endSym; sym++)
            if (!strcmp(symStrings + sym->st_name, name)) {
                    *symp = sym;
                    return (0);
            }
    return (-1);
}

/*
 * Locate a symbol in an ELF image.
 */
int
elfFindSymbolByName(struct ElfObject *o, const char *name, const Elf_Sym **symp)
{
	const Elf_Shdr *hash, *syms;
	const char *symStrings;
	const Elf_Sym *sym;
	Elf_Word nbucket, nchain, i;
	const Elf_Word *buckets, *chains, *hashData;
	unsigned long hashv;

	/* First, search the hashed symbols in .dynsym.  */
	if (elfFindSectionByName(o, ".hash", &hash) == 0) {
		syms = o->sectionHeaders[hash->sh_link];
		hashData = (const Elf_Word *)(o->fileData + hash->sh_offset);
		sym = (const Elf_Sym *)(o->fileData + syms->sh_offset);
		symStrings = (const char *)(o->fileData +
		    o->sectionHeaders[syms->sh_link]->sh_offset);
		nbucket = hashData[0];
		nchain = hashData[1];
		buckets = hashData + 2;
		chains = buckets + nbucket;
		hashv = elf_hash(name) % nbucket;
		for (i = buckets[hashv]; i != STN_UNDEF; i = chains[i])
			if (strcmp(symStrings + sym[i].st_name, name) == 0) {
				*symp = sym + i;
				return (0);
			}
	} else if (elfFindSectionByName(o, ".dynsym", &syms) == 0) {
		/* No ".hash", but have ".dynsym": do linear search */
		if (elfLinearSymSearch(o, syms, name, symp) == 0)
			return (0);
	}
	/* Do a linear search of ".symtab" if present */
	if (elfFindSectionByName(o, ".symtab", &syms) == 0 &&
	    elfLinearSymSearch(o, syms, name, symp) == 0) {
		return (0);
	}
	return (-1);
}

/*
 * Get the data and length from a specific "note" in the ELF file
 */
int
elfGetNotes(struct ElfObject *obj,
		enum NoteIter (*callback)(void *cookie, const char *name,
		u_int32_t type, const void *datap, size_t len), void *cookie)
{
	enum NoteIter iter;
	const Elf_Phdr **phdr;
	const Elf_Note *note;
	const char *noteName;
	const unsigned char *s, *e, *data;

	for (phdr = obj->programHeaders; *phdr; phdr++) {
		if ((*phdr)->p_type == PT_NOTE) {
			s = obj->fileData + (*phdr)->p_offset;
			e = s + (*phdr)->p_filesz;
			while (s < e) {
				note = (const Elf_Note *)s;
				s += sizeof(*note);
				noteName = (const char *)s;
				s += roundup2(note->n_namesz, 4);
				data = s;
				s += roundup2(note->n_descsz, 4);
				iter = callback(cookie, noteName,
					note->n_type, data, note->n_descsz);
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

int
elfGetImageFromCore(struct ElfObject *obj, const char **name)
{
#ifdef __FreeBSD__
	return elfGetNotes(obj, elfImageNote, name);
#endif
#ifdef __linux__
        *name = 0;
        return -1;
#endif
}

/*
 * Attempt to find a prefix to an executable ABI's "emulation tree"
 */
const char *
elfGetAbiPrefix(struct ElfObject *obj)
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
	return 0;
}

/*
 * Free any resources assoiated with an ElfObject
 */
int
elfUnloadObject(struct ElfObject *obj)
{
	struct ElfMemChunk *next, *chunk;
	/* Hack to avoid casting away constness. */
	union {
		void *p;
		const void *cp;
	} u;

	u.cp = obj->fileData;
        if (u.cp)
            munmap(u.p, obj->fileSize);
	for (chunk = obj->mem; chunk != &obj->firstChunk; chunk = next) {
	    next = chunk->next;
	    free(chunk);
	}
	free(obj);
	return (0);
}

/*
 * Culled from System V Application Binary Interface
 */
static unsigned long
elf_hash(const char *name)
{
	const unsigned char *uc = (const unsigned char *)name;
	unsigned long h = 0, g;

	while (*uc != '\0') {
		h = (h << 4) + *uc++;
		if ((g = h & 0xf0000000) != 0)
			h ^= g >> 24;
		h &= ~g;
	}
	return (h);
}

/*
 * Debug output of the contents of an ELF32 section
 */
void
elfDumpSection(FILE *f, struct ElfObject *obj, const Elf_Shdr *hdr,
		size_t snapSize, int indent)
{
	const char *symStrings;
	const Elf_Sym * sym, *esym;
	int i;
	static const char *sectionTypeNames[] = {
		"SHT_NULL",
		"SHT_PROGBITS",
		"SHT_SYMTAB",
		"SHT_STRTAB",
		"SHT_RELA",
		"SHT_HASH",
		"SHT_DYNAMIC",
		"SHT_NOTE",
		"SHT_NOBITS",
		"SHT_REL",
		"SHT_SHLIB",
		"SHT_DYNSYM",
	};

	fprintf(f, "%sname= %s\n", pad(indent), obj->sectionStrings + hdr->sh_name);
	fprintf(f, "%stype= %d (%s)\n",
		pad(indent), hdr->sh_type, hdr->sh_type <= SHT_DYNSYM ?
		sectionTypeNames[hdr->sh_type] : "unknown");
	fprintf(f, "%sflags= %jxH (%s%s%s)\n",
	    pad(indent),
	    (intmax_t)hdr->sh_flags,
	    hdr->sh_flags & SHF_WRITE ? "write " : "",
	    hdr->sh_flags & SHF_ALLOC ? "alloc " : "",
	    hdr->sh_flags & SHF_EXECINSTR ? "instructions " : "");
	fprintf(f, "%saddress= %jxH\n",
	    pad(indent), (intmax_t)hdr->sh_addr);
	fprintf(f, "%soffset= %jd (%jxH)\n", pad(indent),
	    (intmax_t)hdr->sh_offset, (intmax_t)hdr->sh_offset);
	fprintf(f, "%ssize= %jd (%jxH)\n",
	    pad(indent), (intmax_t)hdr->sh_size, (intmax_t)hdr->sh_size);
	fprintf(f, "%slink= %jd (%jxH)\n",
	    pad(indent), (intmax_t)hdr->sh_link, (intmax_t)hdr->sh_link);
	fprintf(f, "%sinfo= %jd (%jxH)\n",
	    pad(indent), (intmax_t)hdr->sh_info, (intmax_t)hdr->sh_info);

	switch (hdr->sh_type) {
	case SHT_SYMTAB:
	case SHT_DYNSYM:
		symStrings = (const char *)(obj->fileData +
		    obj->sectionHeaders[hdr->sh_link]->sh_offset);
		sym = (const Elf_Sym *) (obj->fileData + hdr->sh_offset);
		esym = (const Elf_Sym *) ((const char *)sym + hdr->sh_size);
		for (i = 0; sym < esym; i++, sym++) {
			printf("%ssymbol %d:\n", pad(indent), i);
			elfDumpSymbol(f, sym, symStrings, indent + 4);
		}
		break;
	}
	fprintf(f,"%sstart of data:\n", pad(indent));
	hexdump(f, indent, obj->fileData + hdr->sh_offset,
	    MIN(hdr->sh_size, snapSize));
}

/*
 * Debug output of an ELF32 program segment
 */
void
elfDumpProgramSegment(FILE *f, struct ElfObject *obj, const Elf_Phdr *hdr,
			int indent)
{

	static const char *segmentTypeNames[] = {
		"PT_NULL",
		"PT_LOAD",
		"PT_DYNAMIC",
		"PT_INTERP",
		"PT_NOTE",
		"PT_SHLIB",
		"PT_PHDR"
	};

	fprintf(f, "%stype = %xH (%s)\n",
	    pad(indent), hdr->p_type,
	    hdr->p_type <= PT_PHDR ? segmentTypeNames[hdr->p_type] : "unknown");

	fprintf(f, "%soffset = %jxH (%jd)\n",
	    pad(indent), (intmax_t)hdr->p_offset, (intmax_t)hdr->p_offset);
	fprintf(f, "%svirtual address = %jxH (%jd)\n",
	    pad(indent), (intmax_t)hdr->p_vaddr, (intmax_t)hdr->p_vaddr);
	fprintf(f, "%sphysical address = %jxH (%jd)\n",
	    pad(indent), (intmax_t)hdr->p_paddr, (intmax_t)hdr->p_paddr);
	fprintf(f, "%sfile size = %jxH (%jd)\n",
	    pad(indent), (intmax_t)hdr->p_filesz, (intmax_t)hdr->p_filesz);
	fprintf(f, "%smemory size = %jxH (%jd)\n",
	    pad(indent), (intmax_t)hdr->p_memsz, (intmax_t)hdr->p_memsz);
	fprintf(f, "%sflags = %xH (%s %s %s)\n",
	    pad(indent), hdr->p_flags,
	    hdr->p_flags & PF_R ? "PF_R" : "",
	    hdr->p_flags & PF_W ? "PF_W" : "",
	    hdr->p_flags & PF_X ? "PF_X" : "");

	fprintf(f, "%salignment = %jxH (%jd)\n",
	    pad(indent), (intmax_t)hdr->p_align, (intmax_t)hdr->p_align);

	fprintf(f, "%sstart of data:\n", pad(indent));
	hexdump(f, indent, obj->fileData + hdr->p_offset,
	    MIN(hdr->p_filesz, 64));
}

/*
 * Debug output of an Elf symbol.
 */
void
elfDumpSymbol(FILE *f, const Elf_Sym * sym, const char *strings, int indent)
{
	static const char *bindingNames[] = {
		"STB_LOCAL",
		"STB_GLOBAL",
		"STB_WEAK",
		"unknown3",
		"unknown4",
		"unknown5",
		"unknown6",
		"unknown7",
		"unknown8",
		"unknown9",
		"unknowna",
		"unknownb",
		"unknownc",
		"STB_LOPROC",
		"STB_LOPROC + 1",
		"STB_HIPROC + 1",
	};
	static const char *typeNames[] = {
		"STT_NOTYPE",
		"STT_OBJECT",
		"STT_FUNC",
		"STT_SECTION",
		"STT_FILE",
		"STT_5",
		"STT_6",
		"STT_7",
		"STT_8",
		"STT_9",
		"STT_A",
		"STT_B",
		"STT_C",
		"STT_LOPROC",
		"STT_LOPROC + 1",
		"STT_HIPROC"
	};

	fprintf(f,
	    "%sname = %s\n"
	    "%svalue = %jd (%jxH)\n"
	    "%ssize = %jd (%jxH)\n"
	    "%sinfo = %d (%xH)\n"
	    "%sbinding = %s\n"
	    "%stype = %s\n"
	    "%sother = %d (%xH)\n"
	    "%sshndx = %d (%xH)\n",
	    pad(indent), sym->st_name ? strings + sym->st_name : "(unnamed)",
	    pad(indent), (intmax_t)sym->st_value, (intmax_t)sym->st_value,
	    pad(indent), (intmax_t)sym->st_size, (intmax_t)sym->st_size,
	    pad(indent), sym->st_info, sym->st_info,
	    pad(indent + 4), bindingNames[sym->st_info >> 4],
	    pad(indent + 4), typeNames[sym->st_info & 0xf],
	    pad(indent), sym->st_other, sym->st_other,
	    pad(indent), sym->st_shndx, sym->st_shndx);
}

/*
 * Debug output of an ELF32 dynamic item
 */

void
elfDumpDynamic(FILE *f, const Elf_Dyn *dyn, int indent)
{
	static const char *tagNames[] = {
		"DT_NULL",
		"DT_NEEDED",
		"DT_PLTRELSZ",
		"DT_PLTGOT",
		"DT_HASH",
		"DT_STRTAB",
		"DT_SYMTAB",
		"DT_RELA",
		"DT_RELASZ",
		"DT_RELAENT",
		"DT_STRSZ",
		"DT_SYMENT",
		"DT_INIT",
		"DT_FINI",
		"DT_SONAME",
		"DT_RPATH",
		"DT_SYMBOLIC",
		"DT_REL",
		"DT_RELSZ",
		"DT_RELENT",
		"DT_PLTREL",
		"DT_DEBUG",
		"DT_TEXTREL",
		"DT_JMPREL",
		"DT_BIND_NOW"
	};

	fprintf(f, "%stag: %jd (%s)\n", pad(indent), (intmax_t)dyn->d_tag,
	    dyn->d_tag >= 0 && dyn->d_tag <= DT_BIND_NOW ?
	    tagNames[dyn->d_tag] : "(unknown)");
	fprintf(f, "%sword/addr: %jd (%jx)\n",
	    pad(indent), (intmax_t)dyn->d_un.d_val, (intmax_t)dyn->d_un.d_val);
}

const char *
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

/*
 * Debug output of an ELF32 object.
 */
void
elfDumpObject(FILE *f, struct ElfObject *obj, int snaplen, int indent)
{
	int brand, i;
	static const char *typeNames[] = {
		"ET_NONE",
		"ET_REL",
		"ET_EXEC",
		"ET_DYN",
		"ET_CORE"
	};
	static const char *abiNames[] = {
		"SYSV/NONE",
		"HP-UX",
		"NetBSD",
		"Linux",
		"Hurd",
		"86Open",
		"Solaris",
		"Monterey",
		"Irix",
		"FreeBSD",
		"Tru64",
		"Modesto",
		"OpenBSD"
	};
	const Elf_Ehdr *ehdr = obj->elfHeader;
	const Elf_Dyn *dyn, *edyn;

	brand = ehdr->e_ident[EI_OSABI];
	fprintf(f, "%sType= %s\n", pad(indent), typeNames[ehdr->e_type]);
	fprintf(f, "%sEntrypoint= %jx\n", pad(indent), (intmax_t)ehdr->e_entry);
	fprintf(f, "%sExetype= %d (%s)\n", pad(indent), brand,
		brand >= 0  && brand <= ELFOSABI_OPENBSD ?
		abiNames[brand] : "unknown");
	for (i = 1; i < obj->elfHeader->e_shnum; i++) {
		fprintf(f, "%ssection %d:\n", pad(indent), i);
		elfDumpSection(f, obj, obj->sectionHeaders[i], snaplen,
		    indent + 4);
	}
	for (i = 0; i < obj->elfHeader->e_phnum; i++) {
		fprintf(f, "%ssegment %d:\n", pad(indent), i);
		elfDumpProgramSegment(f, obj, obj->programHeaders[i],
		    indent + 4);
	}
	if (obj->dynamic) {
		dyn = (const Elf_Dyn *)
		    (obj->fileData + obj->dynamic->p_offset);
		edyn = (const Elf_Dyn *)
		    ((const char *)dyn + obj->dynamic->p_filesz);
		while (dyn < edyn) {
			printf("%sdynamic entry\n", pad(indent) - 4);
			elfDumpDynamic(f, dyn, indent + 8);
			dyn++;
		}
	}
	if (obj->interpreterName)
		fprintf(f, "%sinterpreter %s\n", pad(indent), obj->interpreterName);
	elfGetNotes(obj, noteprinter, f);
}

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
    chunk = malloc(sizeof *chunk + chunksize - sizeof chunk->data);
    chunk->next = obj->mem;
    chunk->size = chunksize;
    chunk->used = size;
    obj->mem = chunk;
    return chunk->data;
}

char *
elfStrdup(struct ElfObject *elf, const char *old)
{
    char *new = elfAlloc(elf, strlen(old) + 1);
    strcpy(new, old);
    return new;
}

/*
 * Find the mapped object within which "addr" lies
 */
int
procFindObject(Process *p, Elf_Addr addr, struct ElfObject **objp)
{
    struct ElfObject *obj;
    const Elf_Phdr *phdr;
    int i;

    for (obj = p->objectList; obj; obj = obj->next) {
        Elf32_Addr va = elfAddrProc2Obj(obj, addr);
        for (i = 0; i < obj->elfHeader->e_phnum; i++) {
            phdr = obj->programHeaders[i];
            if (va >= phdr->p_vaddr && va < phdr->p_vaddr + phdr->p_memsz) {
                *objp = obj;
                return (0);
            }
        }
    }
    return (-1);
}
