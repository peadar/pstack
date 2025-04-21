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

#include <string>
#include <vector>
#include <span>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <variant>
#include "libpstack/context.h"
#include "libpstack/json.h"
#include "libpstack/reader.h"
#include "libpstack/stringify.h"

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

namespace pstack::Elf {
class Object;
class SymbolSection;
class NoteDesc;
};

namespace pstack {
std::ostream &operator<< (std::ostream &, const JSON<pstack::Elf::Object> &);
}

namespace pstack::Elf {

#ifndef __FreeBSD__
using Elf32_Note = Elf32_Nhdr;
using Elf64_Note =  Elf64_Nhdr;

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
Type(Sxword);

#if ELF_BITS==64
#define ELF_ST_TYPE ELF64_ST_TYPE
#define IS_ELF(a) true
#endif

#if ELF_BITS==32
#define ELF_ST_TYPE ELF32_ST_TYPE
#define IS_ELF(a) true
#endif

using NamedSymbol = std::pair<Sym, std::string>;
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
    [[nodiscard]] uint32_t bloomoff(size_t idx) const noexcept { return sizeof header + idx * sizeof(Off); }
    [[nodiscard]] uint32_t bucketoff(size_t idx) const noexcept { return bloomoff(header.bloom_size) + idx * 4; }
    [[nodiscard]] uint32_t chainoff(size_t idx) const noexcept { return bucketoff(header.nbuckets) + idx * 4; }
public:
    static const char *tablename() noexcept { return ".gnu.hash"; }
    static int sectiontype() { return SHT_GNU_HASH; }

    GnuHash(Reader::csptr hash_, Reader::csptr syms_, Reader::csptr strings_)
        : hash(std::move(hash_))
        , syms(std::move(syms_))
        , strings(std::move(strings_))
        , header(hash->readObj<Header>(0))
        {}

    std::pair<uint32_t, Sym> findSymbol(const char *) const;
    [[nodiscard]] std::pair<uint32_t, Sym> findSymbol(const std::string &name) const {
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
    Shdr shdr;
    const Elf::Object *elf;
    std::string name;
    explicit operator bool() const { return shdr.sh_type != SHT_NULL; }
    Section(const Object *, Off off);
    Section() : shdr{}, elf{}, name("null") { }
    Section(const Section &) = delete;
    Section(Section &&) = delete;
    Section &operator = (const Section &) = delete;
    Section &operator = (Section &&) = delete;
    Reader::csptr io() const;
};

class Notes {
   const Object *object;
public:
   class iterator;
   class segment_iterator;
   class section_iterator;
   class sentinel {}; // for end.
   [[nodiscard]] iterator begin() const;
   [[nodiscard]] sentinel end() const;
   explicit Notes(const Object *object_) : object(object_) {}
   using value_type = NoteDesc;
};

const Sym &undef();

struct VersionIdx {
   Half idx;
   [[nodiscard]] bool isHidden() const {
       return idx != std::numeric_limits<Half>::max() && ((idx & 0x8000U) != 0 || idx == 0);
   }
   [[nodiscard]] bool isVersioned() const { return (idx & 0x7fffU) > 1; }
   explicit VersionIdx(Half idx) : idx(idx){};
};

/*
 * A symbol section represents a symbol table - this requires two ELF sections,
 * the set of Sym objects, and the section that contains the strings to name
 * those symbols
 */

class SymbolSection {
    Reader::csptr symbols;
    Reader::csptr strings;
    ReaderArray<Sym> array;
public:
    using iterator = ReaderArray<Sym>::iterator;
    iterator begin() { return array.begin(); }
    auto end() { return array.end(); }
    Elf::Sym operator [] (size_t idx) const {
        return symbols->readObj<Sym>(idx * sizeof (Sym));
    }

    SymbolSection(Reader::csptr symbols_, Reader::csptr strings_)
       : symbols(symbols_), strings(strings_), array(*symbols)
    {}
    std::string name(const Sym &sym) const { return strings->readString(sym.st_name); }
};

struct SymbolVersioning {
    std::map<unsigned, std::string> versions;
    std::map<std::string, std::vector<int>> files;
};

class BuildID {
   std::vector<uint8_t> data_;
public:
   using value_type = uint8_t;
   [[nodiscard]] size_t size() const { return data_.size(); }
   [[nodiscard]] const uint8_t *data() const { return data_.data(); }
   [[nodiscard]] uint8_t operator[](size_t idx) const { return data_[idx]; }
   auto operator <=> (const BuildID &) const = default;
   [[nodiscard]] auto begin() const { return data_.begin(); }
   [[nodiscard]] auto end() const { return data_.end(); }
   explicit BuildID(const std::span<uint8_t> &span) : data_(span.begin(), span.end()) {}
   explicit BuildID(std::vector<uint8_t> &&span) : data_(std::move(span)) {}
   explicit operator bool() const { return data_.size() != 0; }
   BuildID() = default;
};

inline std::ostream & operator << (std::ostream &os, const Elf::BuildID &bid) { return os << AsHex(bid); }

// An ELF object - a shared lib, executable, or object file
class Object : public std::enable_shared_from_this<Object> {
public:
    using sptr = std::shared_ptr<Object>;
    using ProgramHeaders = std::vector<Phdr>;
    using Dynamic = std::map<Sxword, std::vector<Dyn>>;
    using ProgramHeadersByType = std::map<Word, ProgramHeaders>;
    using SectionHeaders = std::vector<std::unique_ptr<Section>>;

    // construct/destruct.
    // Note you will generally need to use make_shared to create an Object
    Object(Context &, Reader::csptr, bool isDebug=false);
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

    // Accessing segments.
    const ProgramHeaders &getSegments(Word type) const;
    const std::map<Word, ProgramHeaders> &getAllSegments() const;

    std::optional<std::pair<Sym, std::string>> findSymbolByAddress(Addr addr, int type);

    // Find symbols. The size_t field of the pair is the index within the symbol section
    std::pair<Sym, size_t> findDynamicSymbol(const std::string &name);
    std::pair<Sym, size_t> findDebugSymbol(const std::string &name);

    // Misc operations
    std::string getInterpreter() const;
    const Ehdr &getHeader() const { return elfHeader; }
    const Phdr *getSegmentForAddress(Off) const;
    Notes notes() const { return Notes(this); }
    Addr endVA() const;

    // text description of a symbol's version
    std::optional<std::string> symbolVersion(VersionIdx) const;

    SymbolSection *debugSymbols() const;
    SymbolSection *dynamicSymbols() const;
    const SymbolVersioning &symbolVersions() const;

    BuildID getBuildID() const;

    VersionIdx versionIdxForSymbol( size_t symbolIdx ) const;

    // publically accessible data members.
    Context &context;
    Reader::csptr io;
    const bool isDebug; // this is a debug image.

private:
    Ehdr elfHeader;
    std::optional<std::pair<Sym, std::string>> findSym(auto &table, Addr addr, int type);
    // These are all caches of notionally const data.
    mutable std::unique_ptr<SymbolVersioning> symbolVersions_;
    mutable std::unique_ptr<SectionHeaders> sectionHeaders_;
    mutable std::map<std::string, size_t> namedSection;
    mutable std::shared_ptr<Dynamic> dynamic_;
    mutable std::unique_ptr<SymbolSection> debugSymbols_;
    mutable std::unique_ptr<SymbolSection> dynamicSymbols_;
    mutable Object::sptr debugObject; // debug object as per .gnu_debuglink/other.
    mutable Object::sptr debugData_; // LZMA object in the original elf, .gnu_debugdata.
    mutable bool debugLoaded; // We've at least attempted to load debugObject: don't try again
    mutable std::unique_ptr<SymHash> hash_; // Symbol hash table.
    mutable std::unique_ptr<GnuHash> gnu_hash_; // Enhanced GNU symbol hash table.
    mutable const Phdr *lastSegmentForAddress; // cache of last segment returned for a specific address.

    friend std::ostream &pstack::operator<< (std::ostream &, const pstack::JSON<Object> &);

    // used to cache the debug symbol table by name. Popualted first time something requests such a symbol
    std::unique_ptr<std::map<std::string, size_t>> cachedSymbols;

    ProgramHeadersByType programHeaders_;
    SymbolSection *getSymtab(std::unique_ptr<SymbolSection> &table, const char *name, int type) const;
    Dynamic &dynamic() const;

    const SectionHeaders &sectionHeaders() const;
    Object::sptr debugData() const;

    // Section plumbing for hash and gnu_hash is the same, just with different
    // types and section names, so share the code.
    template <typename HashType> HashType *get_hash(std::unique_ptr<HashType> &ptr) const {
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

    SymHash *hash() const { return get_hash(hash_); }
    GnuHash *gnu_hash() const { return get_hash(gnu_hash_); }
    const Object *getDebug() const; // Gets linked debug object. Note that getSection indirects through this.
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

   NoteDesc(const NoteDesc &rhs) = default;
   NoteDesc(const Note &note_, Reader::csptr io_) : note(note_) , io(io_) { }
   [[nodiscard]] std::string name() const;
   Reader::csptr data() const;
   int type()  const { return note.n_type; }
};

class Notes::segment_iterator {
    const Object *object;
    const Object::ProgramHeaders &phdrs;
    Object::ProgramHeaders::const_iterator phdrsi;
    Off offset;
    Note curNote;
    Reader::csptr io;
    void readNote() { io->readObj(offset, &curNote); }
    void startSection();
public:
    segment_iterator(const Object *object_);
    bool operator == (const segment_iterator &rhs) const {
        return &phdrs == &rhs.phdrs && phdrsi == rhs.phdrsi && offset == rhs.offset;
    }
    bool operator != (const segment_iterator &rhs) const {
        return !(*this == rhs);
    }
    bool operator == (const sentinel &) const {
       return phdrsi == phdrs.end();
    }
    segment_iterator &operator++();
    NoteDesc operator *() {
        return NoteDesc(curNote, io->view("note content", offset));
    }
};

class Notes::section_iterator {
    const Object *object;
    Off sectionIndex;
    Off sectionOffset;
    const Section *section;
    Note curNote;

    bool nextNoteSection();
    void startSection();
    void readNote() { section->io()->readObj(sectionOffset, &curNote); }
public:
    section_iterator(const Object *object_ );

    bool operator == (const section_iterator &rhs) const {
        return object == rhs.object &&
           sectionIndex == rhs.sectionIndex &&
           sectionOffset == rhs.sectionOffset;
    }

    bool operator != (const section_iterator &rhs) const {
        return !(*this == rhs);
    }

    bool operator == (const sentinel &) const {
       return sectionIndex >= object->getHeader().e_shnum;
    }

    section_iterator &operator++();
    NoteDesc operator *() {
        return NoteDesc(curNote, section->io()->view("note content", sectionOffset));
    }
};

class Notes::iterator {
   std::variant<Notes::section_iterator, Notes::segment_iterator> choice;
public:
    iterator(Notes::section_iterator &&it) : choice( it ) {}
    iterator(Notes::segment_iterator &&it) : choice( it ) {}

    bool operator == (const sentinel &rhs) const {
       return std::visit([&rhs](auto &lhs) { return lhs == rhs; }, choice);
    }

    bool operator == (const iterator &rhs) const {
       return choice == rhs.choice;
    }
    bool operator != (const iterator &rhs) const {
       return choice != rhs.choice;
    }
    iterator &operator++() {
       std::visit([](auto &arg) { ++arg; }, choice);
       return *this;
    }
    NoteDesc operator *() {
       return std::visit([](auto &arg) { return *arg; }, choice);
    }
};

enum GNUNotes {
   GNU_BUILD_ID = 3
};

} // Elf namespace

#ifndef NT_FILE
#define NT_FILE 0x46494c45
#endif
#endif /* Guard. */
