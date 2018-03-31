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
extern bool noDebugLibs;

#ifndef elfinfo_h_guard
#define elfinfo_h_guard

#include <sys/procfs.h>
#include <sys/ptrace.h>

#include <elf.h>

#include <tuple>
#include <string>
#include <list>
#include <vector>
#include <map>
#include <memory>
#include <limits>

#include "libpstack/util.h"
#include "libpstack/json.h"

#ifndef ELF_BITS
#define ELF_BITS 64
#endif

#define ELF_WORDSIZE ((ELF_BITS)/8)

class ImageCache;
class ElfObject;
#ifndef __FreeBSD__

#define ElfTypeForBits(type, bits, uscore) typedef Elf##bits##uscore##type Elf##uscore##type ;
#define ElfType2(type, bits) ElfTypeForBits(type, bits, _)
#define ElfType(type) ElfType2(type, ELF_BITS)

#ifndef SHF_COMPRESSED // Old headers may not have SHF_COMPRESSED: define it here.
#define SHF_COMPRESSED (1<<11)
typedef struct {
   Elf32_Word ch_type;
   Elf32_Word ch_size;
   Elf32_Word ch_addralign;
} Elf32_Chdr;

typedef struct {
   Elf64_Word ch_type;
   Elf64_Word ch_size;
   Elf64_Word ch_addralign;
} Elf64_Chdr;
#endif

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
ElfType(Rela)
ElfType(Chdr)
ElfType(Sword)

#if ELF_BITS==64
#define ELF_ST_TYPE ELF64_ST_TYPE
#define IS_ELF(a) true
#endif

#if ELF_BITS==32
#define ELF_ST_TYPE ELF32_ST_TYPE
#define IS_ELF(a) true
#endif


static inline size_t
roundup2(size_t val, size_t align)
{
    return val + (align - (val % align)) % align;
}

#endif

/*
 * Helper class to provide a hashed lookup of a symbol table.
 */
class ElfSymHash {
    Reader::csptr hash;
    Reader::csptr syms;
    Reader::csptr strings;
    Elf_Word nbucket;
    Elf_Word nchain;
    std::vector<Elf_Word> data;
    const Elf_Word *chains;
    const Elf_Word *buckets;
public:
    ElfSymHash(Reader::csptr hash_, Reader::csptr syms_, Reader::csptr strings_);
    bool findSymbol(Elf_Sym &sym, const std::string &name);
};

struct SymbolSection;

/*
 * An ELF section is effectively a pair of an Elf_Shdr to describe an ELF
 * section, and and a reader object in which to find the content.
 */
struct ElfSection {
    Elf_Shdr shdr;
    Reader::csptr io;
    void open(const Reader::csptr &image, off_t off);
    operator bool() const { return shdr.sh_type != SHT_NULL; }
    ElfSection() {
        shdr.sh_type = SHT_NULL;
    }
};

struct ElfNoteIter;
class ElfNoteDesc;

struct ElfNotes {
   ElfNoteIter begin() const;
   ElfNoteIter end() const;
   ElfObject *object;
   ElfNotes(ElfObject *object_) : object(object_) {}
   typedef ElfNoteDesc value_type;
   typedef ElfNoteIter iterator;
};

class ElfObject : public std::enable_shared_from_this<ElfObject> {
public:
    typedef std::shared_ptr<ElfObject> sptr;
    typedef std::vector<Elf_Phdr> ProgramHeaders;
    typedef std::vector<ElfSection> SectionHeaders;

    // construct/destruct. Note you will generally need to use make_shared to
    // create an ElfObject
    ElfObject(ImageCache &, Reader::csptr);
    ~ElfObject();

    // Accessing sections.
    const ElfSection &getSection(Elf_Word idx) const;
    const ElfSection &getLinkedSection(const ElfSection &sec) const;
    const ElfSection &getSection(const std::string &name, Elf_Word type) const;

    // Accessing segments.
    const ProgramHeaders &getSegments(Elf_Word type) const;

    // Accessing symbols
    SymbolSection getSymbols(const std::string &tableName);
    bool findSymbolByAddress(Elf_Addr addr, int type, Elf_Sym &, std::string &);
    bool findSymbolByName(const std::string &name, Elf_Sym &sym);
    bool findHashedSymbol(const std::string &name, Elf_Sym &sym) { return hash ? hash->findSymbol(sym, name) : false; }

    Reader::csptr io;

    // Misc operations
    std::string getInterpreter() const;
    const Elf_Ehdr &getElfHeader() const { return elfHeader; }
    const Elf_Phdr *getSegmentForAddress(Elf_Off) const;
    ElfNotes notes;

private:
    // Elf header, section headers, program headers.
    Elf_Ehdr elfHeader;
    ImageCache &imageCache;
    SectionHeaders sectionHeaders;
    std::map<std::string, ElfSection *> namedSection;
    std::map<Elf_Word, ProgramHeaders> programHeaders;

    mutable bool debugLoaded; // We've at least attempted to load debugObject: don't try again
    mutable ElfObject::sptr debugData; // symbol table data as extracted from .gnu.debugdata
    mutable ElfObject::sptr debugObject; // debug object as per .gnu_debuglink/other.

    std::unique_ptr<ElfSymHash> hash; // Symbol hash table.
    ElfObject *getDebug() const; // Gets linked debug object. Note that getSection indirects through this.
    friend std::ostream &operator<< (std::ostream &, const JSON<ElfObject> &);
    struct CachedSymbol {
        enum { SYM_FOUND, SYM_NOTFOUND, SYM_NEW } disposition;
        Elf_Sym sym;
        CachedSymbol() : disposition { SYM_NEW } {}
    };
    std::map<std::string, CachedSymbol> cachedSymbols;
};

/*
 * See SymbolSection below - provides an iterator for the symbols in a section.
 */
struct SymbolIterator {
    SymbolSection *sec;
    off_t off;
    SymbolIterator(SymbolSection *sec_, off_t off_) : sec(sec_), off(off_) {}
    bool operator != (const SymbolIterator &rhs) { return rhs.off != off; }
    SymbolIterator &operator++ () { off += sizeof (Elf_Sym); return *this; }
    std::pair<const Elf_Sym, const std::string> operator *();
};

/*
 * A symbol section represents a symbol table - this requires two sections, the
 * set of Elf_Sym objects, and the section that contains the strings to name
 * those symbols
 */
struct SymbolSection {
    Reader::csptr symbols;
    Reader::csptr strings;
    SymbolIterator begin() { return SymbolIterator(this, 0); }
    SymbolIterator end() { return SymbolIterator(this, symbols ? symbols->size() : 0); }
    SymbolSection(Reader::csptr symbols_, Reader::csptr strings_)
       : symbols(symbols_), strings(strings_)
    {}
    bool linearSearch(const std::string &name, Elf_Sym &);
};

// These are the architecture specific types representing the NT_PRSTATUS registers.
#if defined(__ARM_ARCH)
struct CoreRegisters {
	elf_gregset_t regs;
};
#elif defined(__PPC)
typedef struct pt_regs CoreRegisters;
#else
typedef struct user_regs_struct CoreRegisters;
#endif

class ElfNoteDesc {
   Elf_Note note;
   Reader::csptr io;
public:

   ElfNoteDesc(const ElfNoteDesc &rhs)
      : note(rhs.note)
      , io(rhs.io)
   {
   }

   std::string name() const;
   Reader::csptr data() const;
   size_t size() const;
   int type()  const { return note.n_type; }
   ElfNoteDesc(const Elf_Note &note_, Reader::csptr io_)
      : note(note_)
      , io(io_)
   {
      io->readObj(0, &note);
   }
   ~ElfNoteDesc() {
   }
};

struct ElfNoteIter {
    ElfObject *object;
    const ElfObject::ProgramHeaders &phdrs;
    ElfObject::ProgramHeaders::const_iterator phdrsi;
    Elf_Off offset;
    Elf_Note curNote;
    Reader::csptr io;

    ElfNoteDesc operator *() {
        return ElfNoteDesc(curNote, std::make_shared<const OffsetReader>(io, offset));
    }

    void startSection() {
        offset = 0;
        io = std::make_shared<OffsetReader>(object->io,
              off_t(phdrsi->p_offset),
              off_t(phdrsi->p_filesz));
    }

    ElfNoteIter &operator++() {
        auto newOff = offset;
        newOff += sizeof curNote + curNote.n_namesz;
        newOff = roundup2(newOff, 4);
        newOff += curNote.n_descsz;
        newOff = roundup2(newOff, 4);
        if (newOff >= phdrsi->p_filesz) {
            if (++phdrsi == phdrs.end()) {
                offset = 0;
                return *this;
            }
            startSection();
        } else {
            offset = newOff;
        }
        readNote();
        return *this;
    }

    ElfNoteIter(ElfObject *object_, bool begin)
        : object(object_)
        , phdrs(object_->getSegments(PT_NOTE))
        , offset(0)
    {
        phdrsi = begin ? phdrs.begin() : phdrs.end();
        if (phdrsi != phdrs.end()) {
            startSection();
            readNote();
        }
    }

    void readNote() {
        io->readObj(offset, &curNote);
    }
    bool operator == (const ElfNoteIter &rhs) const {
        return &phdrs == &rhs.phdrs && phdrsi == rhs.phdrsi && offset == rhs.offset;
    }
    bool operator != (const ElfNoteIter &rhs) const {
        return !(*this == rhs);
    }
};

enum GNUNotes {
   GNU_BUILD_ID = 3
};

/*
 * Places to look for debug images
 */
class GlobalDebugDirectories {
public:
    std::vector<std::string> dirs;
    void add(const std::string &);
    GlobalDebugDirectories() throw();
};
extern GlobalDebugDirectories globalDebugDirectories;

std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr &, const Elf_Sym &> &t);
std::ostream& operator<< (std::ostream &os, const std::pair<const ElfObject *, const Elf_Shdr &> &p);
std::ostream& operator<< (std::ostream &os, const Elf_Phdr &h);
std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr &, const Elf_Sym &> &t);
std::ostream& operator<< (std::ostream &os, const Elf_Dyn &d);
std::ostream& operator<< (std::ostream &os, const ElfObject &obj);

// For platforms that don't have unique_ptr yet.
template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

/*
 * A cache of named files to ELF objects. Note no deduping is done for symbolic
 * links, hard links, or canonicalization of filenames. (XXX: do this with stat
 * & st_ino + st_dev)
 */
class ImageCache {
    std::map<std::string, ElfObject::sptr> cache;
    int elfHits;
    int elfLookups;
public:
    ImageCache();
    ~ImageCache();
    ElfObject::sptr getImageForName(const std::string &name);
    ElfObject::sptr getImageIfLoaded(const std::string &name, bool &found);
    ElfObject::sptr getDebugImage(const std::string &name);
};

#endif /* Guard. */
