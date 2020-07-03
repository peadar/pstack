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
#define ELF_BITS __WORDSIZE
#endif

#define ELF_BYTES ((ELF_BITS)/8)

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

namespace Elf {
class Object;
class ImageCache;
template <typename SymbolType> struct SymbolSection;
class NoteIter;
class NoteDesc;
};

std::ostream &operator<< (std::ostream &, const JSON<Elf::Object> &);

namespace Elf {

#ifndef __FreeBSD__
typedef Elf32_Nhdr Elf32_Note;
typedef Elf64_Nhdr Elf64_Note;

#define TypeForBits(type, bits, uscore) typedef Elf##bits##uscore##type type
#define Type2(type, bits) TypeForBits(type, bits, _)
#define Type(type) Type2(type, ELF_BITS)

Type(Ehdr);
Type(Phdr);
Type(Shdr);
Type(Sym);
Type(Dyn);
Type(Word);
Type(Note);
Type(auxv_t);
Type(Off);
Type(Rela);
Type(Chdr);
Type(Sword);
Type(Addr);
Type(Half);
Type(Verdef);
Type(Verdaux);
Type(Verneed);
Type(Vernaux);

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
 * SymHash provides symbol lookup via ".hash" section hashtable.
 */
class SymHash {
    Reader::csptr hash;
    Reader::csptr syms;
    Reader::csptr strings;
    Word nbucket;
    Word nchain;
    std::vector<Word> data;
    const Word *chains;
    const Word *buckets;
public:
    SymHash(Reader::csptr hash_, Reader::csptr syms_, Reader::csptr strings_);
    uint32_t findSymbol(Sym &sym, const std::string &name); // fills sym, and returns index.
};

/*
 * GnuHash provides symbol lookup via ".gnu.hash" section hashtable. This
 * performs a lot better when looking up a symbol that is not in the table. We
 * use this in preference to SymHash if the image provides the section.
 * https://flapenguin.me/elf-dt-gnu-hash
 */
class GnuHash {
    Reader::csptr hash;
    Reader::csptr syms;
    Reader::csptr strings;
    struct Header {
        uint32_t nbuckets;
        uint32_t symoffset;
        uint32_t bloom_size;
        uint32_t bloom_shift;
    };
    Header header;
    uint32_t bloomoff(size_t idx) const { return sizeof header + idx * sizeof(Elf::Off); }
    uint32_t bucketoff(size_t idx) const { return bloomoff(header.bloom_size) + idx * 4; }
    uint32_t chainoff(size_t idx) const { return bucketoff(header.nbuckets) + idx * 4; }
public:
    GnuHash(const Reader::csptr &hash_, const Reader::csptr &syms_, const Reader::csptr &strings_) :
        hash(hash_), syms(syms_), strings(strings_), header(hash->readObj<Header>(0)) { }
    uint32_t findSymbol(Sym &sym, const char *) const;
    uint32_t findSymbol(Sym &sym, const std::string &name) const {
       return findSymbol(sym, name.c_str());
    }
};

/*
 * An ELF section is effectively a pair of an Shdr to describe an ELF
 * section, and and a reader object in which to find the content.
 */
struct Section {
    Shdr shdr;
    Reader::csptr io;
    operator bool() const { return shdr.sh_type != SHT_NULL; }
    Section(const Reader::csptr &image, off_t off);
    Section() { shdr.sh_type = SHT_NULL; }
    Section(const Section &) = default;
};

struct Notes {
   NoteIter begin() const;
   NoteIter end() const;
   Object *object;
   Notes(Object *object_) : object(object_) {}
   typedef NoteDesc value_type;
   typedef NoteIter iterator;
};

struct NamedSymbol {
   const Sym symbol;
   const std::string name;
   operator bool () const { return symbol.st_shndx != SHN_UNDEF || name != ""; }
   NamedSymbol() : symbol{0, 0, 0, 0, 0, SHN_UNDEF}, name("") { }
   NamedSymbol(const Sym &symbol_, const std::string &name_) : symbol{symbol_}, name{name_} { }
   NamedSymbol(const Sym &symbol_, const Reader::csptr &strings) : symbol{symbol_}, name{strings->readString(symbol.st_name)} { }
};

struct VersionedSymbol : public NamedSymbol {
   int versionIdx;
   VersionedSymbol() : NamedSymbol(), versionIdx(-1) {}
   VersionedSymbol(const Sym &sym_, const std::string &name_, const Section &versionInfo, size_t idx);
   VersionedSymbol(const Sym &sym_, const Reader::csptr &strings, const Section &versionInfo, size_t idx)
       : VersionedSymbol(sym_, strings->readString(sym_.st_name), versionInfo, idx) {}
   bool isHidden() const { return versionIdx != -1 && ((versionIdx & 0x8000) != 0 || versionIdx == 0); }
   bool isVersioned() const { return (versionIdx & 0x7fff) > 1; }
};

/*
 * See SymbolSection below - provides an iterator for the symbols in a section.
 */
template <typename SymbolType>
struct SymbolIterator {
    const SymbolSection<SymbolType> *sec;
    size_t idx;
    SymbolIterator(const SymbolSection<SymbolType> *sec_, size_t idx_) : sec(sec_), idx(idx_) {}
    bool operator != (const SymbolIterator &rhs) { return rhs.idx != idx; }
    SymbolIterator &operator++ () { ++idx; return *this; }
    SymbolType operator *();
};

/*
 * A symbol section represents a symbol table - this requires two sections, the
 * set of Sym objects, and the section that contains the strings to name
 * those symbols
 */
template <typename SymbolType>
struct SymbolSection {
    Object *elf;
    Reader::csptr symbols;
    Reader::csptr strings;
    SymbolIterator<SymbolType> begin() const { return SymbolIterator<SymbolType>(this, 0); }
    SymbolIterator<SymbolType> end() const { return SymbolIterator<SymbolType>(this, symbols ? symbols->size() / sizeof(Sym) : 0); }
    SymbolSection(Object *elf_, Reader::csptr symbols_, Reader::csptr strings_)
       : elf(elf_), symbols(symbols_), strings(strings_)
    {}
    bool linearSearch(const std::string &name, Sym &) const;
};


class Object : public std::enable_shared_from_this<Object> {
public:
    typedef std::shared_ptr<Object> sptr;
    typedef std::vector<Phdr> ProgramHeaders;
    typedef std::vector<Section> SectionHeaders;

    // construct/destruct. Note you will generally need to use make_shared to
    // create an Object
    Object(ImageCache &, Reader::csptr);
    ~Object();

    // Accessing sections.
    const Section &getSection(Word idx) const;
    const Section &getLinkedSection(const Section &sec) const;

    // Get a section by name. If type is not SHT_NULL, the type of the section
    // must match the passed type.
    const Section &getSection(const std::string &name, Word type) const;

    struct CommonSections {

       const Section &dynamic;
       const Section &dynsym;
       const Section &gnu_debugdata;
       const Section &gnu_hash;
       const Section &gnu_version;
       const Section &gnu_version_d;
       const Section &gnu_version_r;
       const Section &hash;
       const Section &symtab;

       const SymbolSection<NamedSymbol> debugSymbols;
       const SymbolSection<VersionedSymbol> dynamicSymbols;

       CommonSections(Object *);
    };

    std::map<int, std::vector<Dyn>> dynamic;

    std::unique_ptr<CommonSections> commonSections;

    // Accessing segments.
    const ProgramHeaders &getSegments(Word type) const;

    bool findSymbolByAddress(Addr addr, int type, Sym &, std::string &);
    VersionedSymbol findDynamicSymbol(const std::string &name);
    NamedSymbol findDebugSymbol(const std::string &name);

    Reader::csptr io;

    // Misc operations
    std::string getInterpreter() const;
    const Ehdr &getHeader() const { return elfHeader; }
    const Phdr *getSegmentForAddress(Off) const;
    Notes notes;
    // symbol table data as extracted from .gnu.debugdata -
    // https://sourceware.org/gdb/current/onlinedocs/gdb/MiniDebugInfo.html
    Elf::Addr endVA() const;

    // find text version from versioned symbol.
    std::string symbolVersion(const VersionedSymbol &) const;
private:
    std::map<int, std::string> symbolVersions;
    // Elf header, section headers, program headers.
    mutable Object::sptr debugData;
    Ehdr elfHeader;
    ImageCache &imageCache;
    SectionHeaders sectionHeaders;
    std::map<std::string, Section *> namedSection;
    std::map<Word, ProgramHeaders> programHeaders;

    mutable bool debugLoaded; // We've at least attempted to load debugObject: don't try again
    mutable Object::sptr debugObject; // debug object as per .gnu_debuglink/other.

    std::unique_ptr<SymHash> hash; // Symbol hash table.
    std::unique_ptr<GnuHash> gnu_hash; // Enhanced GNU symbol hash table.
    Object *getDebug() const; // Gets linked debug object. Note that getSection indirects through this.
    friend std::ostream &::operator<< (std::ostream &, const JSON<Elf::Object> &);
    struct CachedSymbol {
        enum { SYM_FOUND, SYM_NOTFOUND, SYM_NEW } disposition;
        Sym sym;
        CachedSymbol() : disposition { SYM_NEW } {}
    };
    std::map<std::string, CachedSymbol> cachedSymbols;
    mutable const Phdr *lastSegmentForAddress; // cache of last segment returned for a specific address.
};
// These are the architecture specific types representing the NT_PRSTATUS registers.
#if defined(__PPC)
typedef struct pt_regs CoreRegisters;
#else
typedef struct user_regs_struct CoreRegisters;
#endif


/*
 * Describes a note. Notes have a name, a type, and some associated data.
 */
class NoteDesc {
   Note note;
   Reader::csptr io;
public:

   NoteDesc(const NoteDesc &rhs)
      : note(rhs.note)
      , io(rhs.io)
   {
   }

   std::string name() const;
   Reader::csptr data() const;
   int type()  const { return note.n_type; }
   NoteDesc(const Note &note_, Reader::csptr io_)
      : note(note_)
      , io(io_)
   {
      io->readObj(0, &note);
   }
   ~NoteDesc() {
   }
};

/*
 * Iterator over all notes in an image.
 */
class NoteIter {
    Object *object;
    const Object::ProgramHeaders &phdrs;
    Object::ProgramHeaders::const_iterator phdrsi;
    Off offset;
    Note curNote;
    Reader::csptr io;

    void readNote() {
        io->readObj(offset, &curNote);
    }

    void startSection() {
        offset = 0;
        io = std::make_shared<OffsetReader>(object->io,
              off_t(phdrsi->p_offset),
              off_t(phdrsi->p_filesz));
    }

    NoteIter(Object *object_, bool begin)
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
    friend struct Notes;
public:
    bool operator == (const NoteIter &rhs) const {
        return &phdrs == &rhs.phdrs && phdrsi == rhs.phdrsi && offset == rhs.offset;
    }
    bool operator != (const NoteIter &rhs) const {
        return !(*this == rhs);
    }
    NoteIter &operator++() {
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
    NoteDesc operator *() {
        return NoteDesc(curNote, std::make_shared<const OffsetReader>(io, offset));
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

/*
 * A cache of named files to ELF objects. Note no deduping is done for symbolic
 * links, hard links, or canonicalization of filenames. (XXX: do this with stat
 * & st_ino + st_dev)
 */
class ImageCache {
    std::map<std::string, Object::sptr> cache;
    int elfHits;
    int elfLookups;
public:
    ImageCache();
    virtual ~ImageCache();
    virtual void flush(Object::sptr);
    Object::sptr getImageForName(const std::string &name);
    Object::sptr getImageIfLoaded(const std::string &name);
    Object::sptr getDebugImage(const std::string &name);
};

} // Elf namespace
#endif /* Guard. */
