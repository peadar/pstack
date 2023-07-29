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
#include <optional>
#include <utility>


#include "libpstack/json.h"
#include "libpstack/reader.h"

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
   Elf64_Word ch_reserved;
   Elf64_Xword ch_size;
   Elf64_Xword ch_addralign;
} Elf64_Chdr;
#endif

namespace Elf {
class Object;
class ImageCache;
template <typename SymbolType> struct SymbolSection;
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

using NamedSymbol = std::pair<Elf::Sym, std::string>;
using MaybeNamedSymbol = std::optional<NamedSymbol>;

inline size_t
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
    static const char *tablename() { return ".hash"; }
    static int sectiontype() { return SHT_HASH; }
    SymHash(Reader::csptr hash_, Reader::csptr syms_, Reader::csptr strings_);
    std::pair<uint32_t, Sym> findSymbol(const std::string &name); // fills sym, and returns index.
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
    static const char *tablename() { return ".gnu.hash"; }
    static int sectiontype() { return SHT_GNU_HASH; }
    GnuHash(const Reader::csptr &hash_, const Reader::csptr &syms_, const Reader::csptr &strings_) :
        hash(hash_), syms(syms_), strings(strings_), header(hash->readObj<Header>(0)) { }
    std::pair<uint32_t, Sym> findSymbol(const char *) const;
    std::pair<uint32_t, Sym> findSymbol(const std::string &name) const {
       return findSymbol(name.c_str());
    }
};

/*
 * An ELF section is effectively a pair of an Shdr to describe an ELF
 * section, and and a reader object in which to find the content.
 */
class Section {
    mutable Reader::csptr io_;
public:
    Object *elf; // the image in which the section resides.
    std::string name;
    Shdr shdr;
    operator bool() const { return shdr.sh_type != SHT_NULL; }
    Section(Object *io, Off off);
    Section(const Section &) = delete;
    Section() { shdr.sh_type = SHT_NULL; }
    Reader::csptr io() const;
};

class Notes {
   const Object *object;
public:
   class iterator;
   iterator begin() const;
   iterator end() const;
   Notes(const Object *object_) : object(object_) {}
   typedef NoteDesc value_type;
};

const Sym &undef();

// A potentially versioned symbol.  Debug symbols are not versioned, but those
// in the .dynamic section are - In GNU ELF, there's an adjunct tables,
// gnu_version, that has an entry for each symbol in .dynamic, which contains
// an index into the version table. This is essentially an augmentation of the
// Elf{32_64}_Sym - store it alongside here for ease of use.
struct VersionedSymbol : public Sym {
   int versionIdx;
   VersionedSymbol() : Sym(undef()), versionIdx(-1) {}
   VersionedSymbol(const Sym &sym_, const Section &versionInfo, size_t idx);
   bool isHidden() const { return versionIdx != -1 && ((versionIdx & 0x8000) != 0 || versionIdx == 0); }
   bool isVersioned() const { return (versionIdx & 0x7fff) > 1; }
};

/*
 * A symbol section represents a symbol table - this requires two ELF sections,
 * the set of Sym objects, and the section that contains the strings to name
 * those symbols
 */
template <typename SymbolType>
struct SymbolSection {
    struct iterator {
        const SymbolSection<SymbolType> *sec;
        size_t idx;
        iterator(const SymbolSection<SymbolType> *sec_, size_t idx_) : sec(sec_), idx(idx_) {}
        bool operator != (const iterator &rhs) { return rhs.idx != idx; }
        iterator &operator++ () { ++idx; return *this; }
        SymbolType operator *();
    };
    Object *elf;
    Reader::csptr symbols;
    Reader::csptr strings;
    iterator begin() const { return iterator(this, 0); }
    iterator end() const { return iterator(this, symbols ? symbols->size() / sizeof(Sym) : 0); }
    SymbolSection(Object *elf_, Reader::csptr symbols_, Reader::csptr strings_)
       : elf(elf_), symbols(symbols_), strings(strings_)
    {}
    bool linearSearch(const std::string &name, Sym &) const;
    std::string name(const Sym &sym) const { return strings->readString(sym.st_name); }
};

struct SymbolVersioning {
    std::map<int, std::string> versions;
    std::map<std::string, std::vector<int>> files;
};

// An ELF object - a shared lib, executable, or object file
class Object : public std::enable_shared_from_this<Object> {
public:
    typedef std::shared_ptr<Object> sptr;
    typedef std::vector<Phdr> ProgramHeaders;
    // Use pointers so we can avoid copy-construction of Sections.
    typedef std::vector<std::unique_ptr<Section>> SectionHeaders;

    // construct/destruct. Note you will generally need to use make_shared to
    // create an Object
    Object(ImageCache &, Reader::csptr, bool isDebug=false);
    ~Object() noexcept = default;

    // Accessing sections.
    const Section &getSection(Word idx) const;
    const Section &getLinkedSection(const Section &sec) const;

    // Get a section by name. If type is not SHT_NULL, the type of the section
    // must match the passed type.
    const Section &getSection(const std::string &name, Word type) const;

    // Get a "debug" section. the content of this section may be in this
    // object, or the associated debug ELF object.
    const Section &getDebugSection(const std::string &name, Word type) const;

    std::map<int, std::vector<Dyn>> dynamic;

    // Accessing segments.
    const ProgramHeaders &getSegments(Word type) const;

    std::optional<std::pair<Sym, std::string>> findSymbolByAddress(Addr addr, int type);
    VersionedSymbol findDynamicSymbol(const std::string &name);
    Sym findDebugSymbol(const std::string &name);

    Reader::csptr io;

    // Misc operations
    std::string getInterpreter() const;
    const Ehdr &getHeader() const { return elfHeader; }
    const Phdr *getSegmentForAddress(Off) const;
    Notes notes() const { return Notes(this); }
    // symbol table data as extracted from .gnu.debugdata -
    // https://sourceware.org/gdb/current/onlinedocs/gdb/MiniDebugInfo.html
    Elf::Addr endVA() const;

    // find text version from versioned symbol.
    std::string symbolVersion(const VersionedSymbol &) const;
    SymbolSection<Sym> *debugSymbols();
    SymbolSection<VersionedSymbol> * dynamicSymbols();
    const SymbolVersioning *symbolVersions() const;
    const Section *gnu_version;
private:
    mutable std::unique_ptr<SymbolVersioning> symbolVersions_;
    // Elf header, section headers, program headers.
    mutable Object::sptr debugData;
    Ehdr elfHeader;
    ImageCache &imageCache;
    SectionHeaders sectionHeaders;
    std::map<std::string, size_t> namedSection;
    std::map<Word, ProgramHeaders> programHeaders;

    std::unique_ptr<SymbolSection<Sym>> debugSymbols_;

    std::unique_ptr<SymbolSection<VersionedSymbol>> dynamicSymbols_;

    template<typename Symtype>
    SymbolSection<Symtype> *getSymtab(std::unique_ptr<SymbolSection<Symtype>> &table, const char *name, int type);

    mutable bool debugLoaded; // We've at least attempted to load debugObject: don't try again
    mutable Object::sptr debugObject; // debug object as per .gnu_debuglink/other.

    // Section plumbing for hash and gnu_hash is the same, just with different
    // types and section names, so share the code.
    template <typename HashType> HashType *get_hash(std::unique_ptr<HashType> &ptr) {
        if (ptr == nullptr) {
            auto &section { getSection( HashType::tablename(), HashType::sectiontype() ) };
            if (section) {
                auto &syms = getLinkedSection(section);
                auto &strings = getLinkedSection(syms);
                if (syms && strings)
                    ptr = std::make_unique<HashType>(section.io(), syms.io(), strings.io());
            }
        }
        return ptr.get();
    }

    std::unique_ptr<SymHash> hash_; // Symbol hash table.
    SymHash *hash() { return get_hash(hash_); }
    std::unique_ptr<GnuHash> gnu_hash_; // Enhanced GNU symbol hash table.
    GnuHash *gnu_hash() { return get_hash(gnu_hash_); }

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

inline Addr getReg(const CoreRegisters &regs, int reg) {
#define REGMAP(regno, field) case regno: return regs.field;
    switch (reg) {
#include "libpstack/archreg.h"
    }
#undef REGMAP
    return 0;
};

inline void setReg(CoreRegisters &regs, int reg, Addr val) {
#define REGMAP(regno, field) case regno: regs.field = val; break;
    switch (reg) {
#include "libpstack/archreg.h"
    }
#undef REGMAP
};

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
   ~NoteDesc() noexcept = default;
};

class Notes::iterator {
    const Object *object;
    const Object::ProgramHeaders &phdrs;
    Object::ProgramHeaders::const_iterator phdrsi;
    Off offset;
    Note curNote;
    Reader::csptr io;
    void readNote() { io->readObj(offset, &curNote); }
    void startSection();
public:
    iterator(const Object *object_, bool begin);
    bool operator == (const iterator &rhs) const {
        return &phdrs == &rhs.phdrs && phdrsi == rhs.phdrsi && offset == rhs.offset;
    }
    bool operator != (const iterator &rhs) const {
        return !(*this == rhs);
    }
    iterator &operator++();
    NoteDesc operator *() {
        return NoteDesc(curNote, std::make_shared<const OffsetReader>("note content", io, offset));
    }
};

enum GNUNotes {
   GNU_BUILD_ID = 3
};

/*
 * Places to look for debug images
 */

extern std::vector<std::string> globalDebugDirectories;

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
    virtual ~ImageCache() noexcept;
    virtual void flush(Object::sptr);
    Object::sptr getImageForName(const std::string &name, bool isDebug = false);
    Object::sptr getImageIfLoaded(const std::string &name);
    Object::sptr getDebugImage(const std::string &name);
};

extern bool noExtDebug; // if set, don't look for exernal ELF info, i.e., usinb debuglink, or buildid.

} // Elf namespace

#ifndef NT_FILE
#define NT_FILE 0x46494c45
#endif
#endif /* Guard. */
