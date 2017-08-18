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

#include <tuple>
#include <string>
#include <sys/ptrace.h>
#include <list>
#include <vector>
#include <map>
#include <memory>
#include <elf.h>
#include <sys/procfs.h>
#include <libpstack/util.h>
#include <limits>


/*
 * FreeBSD defines all elf types with a common header, defining the
 * 64 and 32 bit versions through a common body, giving us platform
 * independent names for each one. We work backwards on Linux to
 * provide the same handy naming.
 */


#ifndef ELF_BITS
#define ELF_BITS 64
#endif

#define ELF_WORDSIZE ((ELF_BITS)/8)

class ElfObject;
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
ElfType(Rela)
ElfType(Chdr)

#if ELF_BITS==64
#define ELF_ST_TYPE ELF64_ST_TYPE
#define IS_ELF(a) 1
#endif

#if ELF_BITS==32
#define ELF_ST_TYPE ELF32_ST_TYPE
#define IS_ELF(a) 1
#endif


static inline size_t
roundup2(size_t val, size_t align)
{
    return val + (align - (val % align)) % align;
}

#endif

class ElfSymHash;
struct SymbolSection;

enum NoteIter {
    NOTE_CONTIN,
    NOTE_ERROR,
    NOTE_DONE
};

struct ElfSection {
    const Elf_Shdr *shdr;
    size_t realLength;
    std::shared_ptr<Reader> io;
    operator bool() const { return shdr != nullptr; }
    ElfSection(const ElfObject &obj_, const Elf_Shdr *shdr_);
    ElfSection() = delete;
    ElfSection(const ElfSection &) = delete;
};

struct ElfNoteIter;

struct ElfNotes {
   ElfNoteIter begin() const;
   ElfNoteIter end() const;
   ElfObject *object;
   ElfNotes(ElfObject *object_) : object(object_) {}
};

class ElfObject {
public:
    typedef std::vector<Elf_Phdr> ProgramHeaders;
    typedef std::vector<Elf_Shdr> SectionHeaders;
private:
    mutable std::map<const Elf_Shdr *, std::shared_ptr<ElfSection>> elfSections;
    friend std::ostream &operator<< (std::ostream &os, const ElfObject &obj);
    std::shared_ptr<Reader> io; // IO for the ELF image.
    size_t fileSize;
    Elf_Ehdr elfHeader;
    std::map<Elf_Word, ProgramHeaders> programHeaders;
    std::unique_ptr<ElfSymHash> hash;
    void init(const std::shared_ptr<Reader> &); // want constructor chaining
    std::map<std::string, Elf_Shdr *> namedSection;
    std::string name;
    bool debugLoaded;
    std::shared_ptr<ElfObject> debugObject;
    std::shared_ptr<const ElfSection> getSection(const Elf_Shdr *idx) const;
public:
    std::shared_ptr<ElfObject> getDebug();
    static std::shared_ptr<ElfObject> getDebug(std::shared_ptr<ElfObject> &);
    SymbolSection getSymbols(const std::string &table);
    SectionHeaders sectionHeaders;
    Elf_Off getBase() const; // lowest address of a PT_LOAD segment.
    std::string getInterpreter() const;
    std::string getName() const { return name; }
    std::shared_ptr<const ElfSection> getSection(Elf_Word idx) const;
    const SectionHeaders &getSections() const { return sectionHeaders; }
    const ProgramHeaders &getSegments(Elf_Word type) const {
        auto it = programHeaders.find(type);
        if (it == programHeaders.end()) {
            static const ProgramHeaders empty;
            return empty;
        }
        return it->second;
    }
    std::shared_ptr<const ElfSection> getSection(const std::string &name, Elf_Word type) const;
    const Elf_Ehdr &getElfHeader() const { return elfHeader; }
    bool findSymbolByAddress(Elf_Addr addr, int type, Elf_Sym &, std::string &);
    bool findSymbolByName(const std::string &name, Elf_Sym &sym);
    ElfObject(std::shared_ptr<Reader>);
    ElfObject(const std::string &name);
    ~ElfObject();
    const Elf_Phdr *findHeaderForAddress(Elf_Off) const;
    bool findDebugInfo();
    ElfNotes notes;
    std::shared_ptr<Reader> getio() const { return io; }
    bool linearSymSearch(std::shared_ptr<const ElfSection> hdr, const std::string &name, Elf_Sym &);
};

// Helpful for iterating over symbol sections.
struct SymbolIterator {
    SymbolSection *sec;
    off_t off;
    SymbolIterator(SymbolSection *sec_, off_t off_) : sec(sec_), off(off_) {}
    bool operator != (const SymbolIterator &rhs) { return rhs.off != off; }
    SymbolIterator &operator++ () { off += sizeof (Elf_Sym); return *this; }
    std::pair<const Elf_Sym, const std::string> operator *();
};

struct SymbolSection {
    std::shared_ptr<const ElfSection> symbols;
    std::shared_ptr<const ElfSection> strings;
    SymbolIterator begin() { return SymbolIterator(this, 0); }
    SymbolIterator end() { return SymbolIterator(this, symbols->shdr->sh_size); }
    SymbolSection(ElfObject &elf, std::shared_ptr<const ElfSection> symbols_)
        : symbols(symbols_)
        , strings(elf.getSection(symbols->shdr->sh_link))
    {}
};

class ElfSymHash {
    std::shared_ptr<const ElfSection> hash;
    std::shared_ptr<const ElfSection> syms;
    std::shared_ptr<const ElfSection> strings;
    Elf_Word nbucket;
    Elf_Word nchain;
    std::vector<Elf_Word> data;
    const Elf_Word *chains;
    const Elf_Word *buckets;
public:
    ElfSymHash(std::shared_ptr<const ElfSection> &hash, std::shared_ptr<const ElfSection> &syms, std::shared_ptr<const ElfSection> &strings_);
    bool findSymbol(Elf_Sym &sym, const std::string &name);
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
   std::shared_ptr<Reader> io;
   mutable unsigned char *databuf;
public:
   ElfNoteDesc(const ElfNoteDesc &rhs)
      : note(rhs.note)
      , io(rhs.io)
      , databuf(0)
   {
      if (rhs.databuf) {
         databuf = new unsigned char[rhs.size()];
         memcpy(databuf, rhs.databuf, rhs.size());
      }
   }
   std::string name() const;
   const unsigned char *data() const;
   size_t size() const;
   int type()  const { return note.n_type; }
   ElfNoteDesc(const Elf_Note &n, std::shared_ptr<Reader> io_)
      : note(n)
      , io(io_)
      , databuf(0)
   {}
   ~ElfNoteDesc() {
      delete[] databuf;
   }
};

struct ElfNoteIter {
    ElfObject *object;
    const ElfObject::ProgramHeaders &phdrs;
    ElfObject::ProgramHeaders::const_iterator phdrsi;
    Elf_Off offset;
    Elf_Note curNote;
    std::shared_ptr<Reader> io;

    ElfNoteDesc operator *() {
        return ElfNoteDesc(curNote, std::make_shared<OffsetReader>(io, offset, std::numeric_limits<off_t>::max()));
    }

    void startSection() {
        offset = 0;
        io = std::make_shared<OffsetReader>(object->getio(), off_t(phdrsi->p_offset), off_t(phdrsi->p_filesz));
    }

    ElfNoteIter &operator++() {
        auto newOff = offset;
        newOff += sizeof curNote + curNote.n_namesz;
        newOff = roundup2(newOff, 4);
        newOff += curNote.n_descsz;
        newOff = roundup2(newOff, 4);
        if (newOff >= phdrsi->p_filesz) {
            if (++phdrsi == phdrs.end())
                return *this;
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

class GlobalDebugDirectories {
public:
    std::vector<std::string> dirs;
    void add(const std::string &);
    GlobalDebugDirectories();
};
extern GlobalDebugDirectories globalDebugDirectories;

std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr &, const Elf_Sym &> &t);
std::ostream& operator<< (std::ostream &os, const std::pair<const ElfObject *, const Elf_Shdr &> &p);
std::ostream& operator<< (std::ostream &os, const Elf_Phdr &h);
std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr &, const Elf_Sym &> &t);
std::ostream& operator<< (std::ostream &os, const Elf_Dyn &d);
std::ostream& operator<< (std::ostream &os, const ElfObject &obj);

template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

#endif /* Guard. */
