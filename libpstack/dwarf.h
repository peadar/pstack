#ifndef DWARF_H
#define DWARF_H

#include <libpstack/elf.h>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <stack>
#include <string>
#include <unordered_map>
#include <vector>
#include <iterator>
#include <cassert>

namespace Dwarf {

enum HasChildren { DW_CHILDREN_yes = 1, DW_CHILDREN_no = 0 };

class Attribute;
class DIE;
class DIEIter;
class DWARFReader;
class ExpressionStack;
class Info;
class LineInfo;
class RawDIE;
class Unit;
struct CFI;
struct CIE;

typedef std::vector<size_t> Entries;

#define DWARF_TAG(a,b) a = b,
enum Tag {
#include <libpstack/dwarf/tags.h>
    DW_TAG_none = 0x0
};
#undef DWARF_TAG

#define DWARF_ATE(a,b) a = b,
enum Encoding {
#include <libpstack/dwarf/encodings.h>
    DW_ATE_none = 0x0
};
#undef DWARF_ATE

#define DWARF_UNIT_TYPE(a,b) a = b,
enum UnitType {
#include <libpstack/dwarf/unittype.h>
    DW_UT_none
};
#undef DWARF_UNIT_TYPE

#define DWARF_FORM(a,b) a = b,
enum Form {
#include <libpstack/dwarf/forms.h>
    DW_FORM_none = 0x0
};
#undef DWARF_FORM

#define DWARF_ATTR(a,b) a = b,
enum AttrName {
#include <libpstack/dwarf/attr.h>
    DW_AT_none = 0x0
};

}
namespace std {
   template <> struct hash<Dwarf::AttrName> {
      size_t operator() (Dwarf::AttrName name) const { return size_t(name); }
   };
}
namespace Dwarf {
#undef DWARF_ATTR

#define DWARF_LINE_S(a,b) a = b,
enum LineSOpcode {
#include <libpstack/dwarf/line_s.h>
    DW_LNS_none = -1
};
#undef DWARF_LINE_S

#define DWARF_LINE_E(a,b) a = b,
enum LineEOpcode {
#include <libpstack/dwarf/line_e.h>
    DW_LNE_none = -1
};
#undef DWARF_LINE_E

struct FormEntry {
    Form form;
    intmax_t value;
    FormEntry(Form f, intmax_t v) : form(f), value(v) {}
};

struct Abbreviation {
    Tag tag;
    bool hasChildren;
    std::vector<FormEntry> forms;
    using AttrNameMap = std::unordered_map<AttrName, size_t>;
    int nextSibIdx;
    AttrNameMap attrName2Idx;
    Abbreviation(DWARFReader &);
    Abbreviation() {}
};

struct Pubname {
    uint32_t offset;
    std::string name;
    Pubname(DWARFReader &r, uint32_t offset);
};

struct PubnameUnit {
    uint16_t length;
    uint16_t version;
    uint32_t infoOffset;
    uint32_t infoLength;
    std::list<Pubname> pubnames;
    PubnameUnit(DWARFReader &r);
};

struct Block {
   Elf::Off offset;
   Elf::Off length;
};

union Value {
    uintmax_t addr;
    uintmax_t signature;
    uintmax_t udata;
    intmax_t sdata;
    Block *block;
    bool flag;
};

class DIEChildren {
    const DIE &parent;
public:
    DIEChildren(const DIE &parent_) : parent(parent_) {}
    DIEIter begin() const;
    DIEIter end() const;
    using const_iterator = DIEIter;
    using value_type = DIE;
};

class DIEAttributes {
    const DIE &die;
public:
    using value_type = std::pair<AttrName, Attribute>;
    using mapped_type = Attribute;
    using key_type = AttrName;
    struct const_iterator {
        const DIE &die;
        Abbreviation::AttrNameMap::const_iterator rawIter;
        std::pair<AttrName, Attribute> operator *() const;
        const_iterator &operator++() {
            ++rawIter;
            return *this;
        }
        const_iterator(const DIE &die_, Abbreviation::AttrNameMap::const_iterator rawIter_) : 
            die(die_), rawIter(rawIter_) {}
        bool operator == (const const_iterator &rhs) const {
            return rawIter == rhs.rawIter;
        }
        bool operator != (const const_iterator &rhs) const {
            return rawIter != rhs.rawIter;
        }
    };
    const_iterator begin() const;
    const_iterator end() const;
    DIEAttributes(const DIE &die) : die(die) {}
};

enum class ContainsAddr { YES, NO, UNKNOWN };

class DIE {
    std::shared_ptr<Unit> unit;
    Elf::Off offset;
public:
    std::shared_ptr<RawDIE> raw;
    friend class DIEIter;
    friend class Attribute;
    friend class DIEAttributes;
    friend class RawDIE;
    ContainsAddr containsAddress(Elf::Addr addr) const;
    Elf::Off getParentOffset() const;
    Elf::Off getOffset() const { return offset; }
    const std::shared_ptr<Unit> & getUnit() const { return unit; }
    DIE(const std::shared_ptr<Unit> &unit, size_t offset_, const std::shared_ptr<RawDIE> &raw) : unit(unit), offset(offset_), raw(raw) {}
    DIE() : unit(nullptr), offset(0), raw(nullptr) {}
    operator bool() const { return raw != nullptr; }
    Attribute attribute(AttrName name, bool local = false) const;
    inline std::string name() const;
    DIEAttributes attributes() const { return DIEAttributes(*this); }
    Tag tag() const;
    bool hasChildren() const;
    DIE hasNextSibling() const;
    DIE firstChild() const;
    DIE nextSibling(const DIE &parent) const;
    DIEChildren children() const { return DIEChildren(*this); }
};

using Ranges = std::vector<std::pair<uintmax_t, uintmax_t>>;
class Attribute {
    DIE dieref;
    const FormEntry *formp; /* From abbrev table attached to type */

    Value &value();
public:
    const DIE &die() const { return dieref; }
    const Value &value() const;
    Form form() const { return formp->form; }
    Attribute(const DIE &dieref_, const FormEntry *formp_)
       : dieref(dieref_), formp(formp_) {}
    Attribute() : formp(nullptr) {}
    ~Attribute() { }

    bool valid() const { return formp != nullptr; }
    explicit operator std::string() const;
    explicit operator intmax_t() const;
    explicit operator uintmax_t() const;
    explicit operator bool() const { return valid() && value().flag; }
    explicit operator DIE() const;
    explicit operator const Block &() const { return *value().block; }
    explicit operator Ranges () const;
    AttrName name() const;
};

std::string
DIE::name() const
{
    auto attr = attribute(DW_AT_name);
    return attr.valid() ? std::string(attr) : "";
}

enum FIType {
    FI_DEBUG_FRAME,
    FI_EH_FRAME
};

class FileEntry {
public:
    FileEntry() = default;
    FileEntry(const FileEntry &) = default;
    std::string name;
    unsigned dirindex;
    unsigned lastMod;
    unsigned length;
    FileEntry(std::string name_, unsigned dirindex, unsigned lastMod_, unsigned length_);
    FileEntry(DWARFReader &r);
};

class LineState {
    LineState() = delete;
public:
    FileEntry *file;
    uintmax_t addr;
    unsigned line;
    unsigned column;
    bool is_stmt:1;
    bool basic_block:1;
    bool end_sequence:1;
    bool prologue_end:1;
    bool epilogue_begin:1;
    unsigned isa;
    unsigned discriminator;
    LineState(LineInfo *);
};

class LineInfo {
    LineInfo(const LineInfo &) = delete;
public:
    LineInfo() {}
    bool default_is_stmt;
    uint8_t opcode_base;
    std::vector<int> opcode_lengths;
    std::vector<std::string> directories;
    std::vector<FileEntry> files;
    std::vector<LineState> matrix;
    void build(DWARFReader &, const Unit *);
};

struct MacroVisitor;
struct Macros {
    Reader::csptr reader;
    uint16_t version;
    int dwarflen;
    int debug_line_offset;
    std::map<uint8_t, std::vector<uint8_t>> opcodes;
    Macros(const Info *info, intmax_t offset);
    bool visit(const Info *, MacroVisitor *) const;
};

class Unit : public std::enable_shared_from_this<Unit> {
    Unit() = delete;
    Unit(const Unit &) = delete;
    Elf::Off abbrevOffset;
    std::unique_ptr<LineInfo> lines;
    std::unordered_map<size_t, Abbreviation> abbreviations;
    
    Elf::Off topDIEOffset;
    using AllEntries = std::unordered_map<Elf::Off, std::shared_ptr<RawDIE>>;
    AllEntries allEntries;
    std::shared_ptr<RawDIE> decodeEntry(const DIE &parent, Elf::Off offset);
    UnitType unitType;
    mutable std::unique_ptr<Macros> macros;
    void load();
public:
    void purge(); // Remove all RawDIEs from allEntries, potentially freeing memory.
    bool isRoot(const DIE &die) { return die.getOffset() == topDIEOffset; }
    size_t entryCount() const { return allEntries.size(); }
    typedef std::shared_ptr<Unit> sptr;
    typedef std::shared_ptr<const Unit> csptr;
    const Abbreviation *findAbbreviation(size_t) const;
    DIE root() {
       if (abbreviations.empty())
          load();
       return offsetToDIE(topDIEOffset);
    }
    DIE offsetToDIE(Elf::Off offset);
    DIE offsetToDIE(const DIE &parent, Elf::Off offset);
    std::shared_ptr<RawDIE> offsetToRawDIE(const DIE &parent, Elf::Off offset);
    const Info *dwarf;
    Reader::csptr io;

    // header fields
    Elf::Off offset;
    uint32_t length;
    Elf::Off end; // a.k.a. start of next unit.
    uint16_t version;
    size_t dwarfLen;
    uint8_t addrlen;
    Unit(const Info *, DWARFReader &);
    std::string name();
    const LineInfo *getLines();
    const Macros *getMacros();
    ~Unit();
    unsigned char id[8]; // Unit ID for DWO.
};

class UnitIterator {
    const Info *info;
    Unit::sptr currentUnit;
    bool atend() const;
public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = Unit::sptr;
    using difference_type = int;
    using pointer = Unit::sptr *;
    using reference = Unit::sptr &;
    Unit::sptr operator *() { return currentUnit; }
    UnitIterator operator ++();
    bool operator == (const UnitIterator &rhs) const {
        if (atend() || rhs.atend())
            return atend() == rhs.atend();
        return info == rhs.info && currentUnit->offset == rhs.currentUnit->offset;
    }
    bool operator != (const UnitIterator &rhs) const {
        return !(*this == rhs);
    }
    UnitIterator(const Info *info_, Elf::Off offset);
    UnitIterator() : info(nullptr), currentUnit(nullptr) {}
};

struct Units {
    using value_type = Unit::sptr;
    using iterator = UnitIterator;
    using const_iterator = UnitIterator;
    std::shared_ptr<const Info> info;
    UnitIterator begin() const;
    UnitIterator end() const { return iterator(); }
    Units(const std::shared_ptr<const Info> &info_) : info(info_) {}
};

struct UnitsCache {
    std::map<Elf::Off, Unit::sptr> byOffset;
    std::list<Unit::sptr> LRU;
    Unit::sptr get(const Info *, Elf::Off);
    Unit::sptr unitForDIE(const Info *, Elf::Off offset);
};

struct FDE {
    uintmax_t iloc;
    uintmax_t irange;
    Elf::Off instructions;
    Elf::Off end;
    Elf::Off cieOff;
    std::vector<unsigned char> augmentation;
    FDE(CFI *, DWARFReader &, Elf::Off cieOff_, Elf::Off endOff_);
};

enum RegisterType {
    UNDEF,
    SAME,
    OFFSET,
    VAL_OFFSET,
    EXPRESSION,
    VAL_EXPRESSION,
    REG,
    ARCH
};

struct RegisterUnwind {
    enum RegisterType type;
    union {
        uintmax_t same;
        intmax_t offset;
        uintmax_t reg;
        Block expression;
        uintmax_t arch;
    } u;
};

struct CallFrame {
    std::map<int, RegisterUnwind> registers;
    int cfaReg;
    RegisterUnwind cfaValue;
    CallFrame();
    // default copy constructor is valid.
};

struct CIE {
    const CFI *frameInfo;
    uint8_t version;
    uint8_t addressEncoding;
    uint8_t addressSize;
    uint8_t segmentSize;
    unsigned char lsdaEncoding;
    bool isSignalHandler;
    unsigned codeAlign;
    int dataAlign;
    int rar;
    Elf::Off instructions;
    Elf::Off end;
    uintmax_t personality;
    std::string augmentation;
    CIE(const CFI *, DWARFReader &, Elf::Off);
    CIE() {}
    CallFrame execInsns(DWARFReader &r, uintmax_t addr, uintmax_t wantAddr) const;
};

/*
 * CFI represents call frame information (generally contents of .debug_frame or .eh_frame)
 */
struct CFI {
    const Info *dwarf;
    Elf::Addr sectionAddr; // virtual address of this section  (may need to be offset by load address)
    Reader::csptr io;
    FIType type;
    std::map<Elf::Addr, CIE> cies;
    std::list<FDE> fdeList;
    CFI(Info *, Elf::Addr addr, Reader::csptr io, FIType);
    CFI() = delete;
    CFI(const CFI &) = delete;
    Elf::Addr decodeCIEFDEHdr(DWARFReader &, FIType, Elf::Off *cieOff); // cieOFF set to -1 if this is CIE, set to offset of associated CIE for an FDE
    const FDE *findFDE(Elf::Addr) const;
    bool isCIE(Elf::Addr);
    intmax_t decodeAddress(DWARFReader &, int encoding) const;
};

struct ARanges {
    std::map<Elf::Addr, std::pair<Elf::Addr, Elf::Off>> ranges;
};

class ImageCache;
/*
 * Info represents all the interesting bits of the DWARF data.
 * It's primary function is to provide access to the DIE tree.
 */
class Info : public std::enable_shared_from_this<Info> {
public:
    Info(Elf::Object::sptr, ImageCache &);
    ~Info();
    typedef std::shared_ptr<Info> sptr;
    typedef std::shared_ptr<const Info> csptr;
    Reader::csptr io; // XXX: io is public because "block" Attributes need to read from it.
    std::map<Elf::Addr, CallFrame> callFrameForAddr;
    Elf::Object::sptr elf;
    std::unique_ptr<CFI> debugFrame;
    std::unique_ptr<CFI> ehFrame;
    Reader::csptr debugStrings;
    Reader::csptr debugLineStrings;
    Reader::csptr abbrev;
    Reader::csptr lineshdr;
    Info::sptr getAltDwarf() const;
    const ARanges &getARanges() const;
    const std::list<PubnameUnit> &pubnames() const;
    Unit::sptr getUnit(Elf::Off offset) const;
    Units getUnits() const;
    DIE offsetToDIE(Elf::Off) const;
    bool hasRanges() const { return bool(rangesh); }
    bool hasARanges() const;
    Unit::sptr lookupUnit(Elf::Addr addr) const;
    std::vector<std::pair<std::string, int>> sourceFromAddr(uintmax_t addr) const;
    mutable Reader::csptr strOffsets;
    LineInfo *linesAt(intmax_t, const Unit *) const;

private:
    void decodeARangeSet(DWARFReader &) const;
    std::string getAltImageName() const;
    mutable std::list<PubnameUnit> pubnameUnits;
    // These are mutable so we can lazy-eval them when getters are called, and
    // maintain logical constness.
    mutable UnitsCache units;
    mutable Info::sptr altDwarf;
    mutable bool altImageLoaded;
    ImageCache &imageCache;
    mutable Reader::csptr pubnamesh;
    mutable Reader::csptr arangesh;
public:
    mutable Reader::csptr rangesh;
    mutable Reader::csptr macrosh;
private:
    mutable ARanges aranges; // maps starting address to length + unit offset.
    bool haveLines;
    bool haveARanges;
    mutable bool unitRangesCached = false;
    mutable std::unique_ptr<Macros> macros;
};

/*
 * A Dwarf Image Cache is an (Elf) ImageCache, but caches Dwarf::Info for the
 * Objects also.
 */
class ImageCache : public Elf::ImageCache {
    int dwarfHits;
    int dwarfLookups;
    std::map<Elf::Object::sptr, Info::sptr> dwarfCache;
public:
    Info::sptr getDwarf(const std::string &);
    Info::sptr getDwarf(Elf::Object::sptr);
    void flush(Elf::Object::sptr);
    ImageCache();
    ~ImageCache();
};

class DIEIter {
    const std::shared_ptr<const Unit> u;
    DIE parent;
    DIE currentDIE;
    DIEIter(const DIE &first, const DIE & parent_);
    friend DIEChildren;
public:
    const DIE &operator *() const { return currentDIE; }

    DIEIter &operator++();

    bool operator == (const DIEIter &rhs) const {
        if (!currentDIE)
            return !rhs.currentDIE;
        if (!rhs.currentDIE)
            return false;
        return currentDIE.unit == rhs.currentDIE.unit &&
            currentDIE.offset == rhs.currentDIE.offset;
    }
    bool operator != (const DIEIter &rhs) const {
        return !(*this == rhs);
    }
};

enum CFAInstruction {
#define DWARF_CFA_INSN(name, value) name = value,
#include "libpstack/dwarf/cfainsns.h"
#undef DWARF_CFA_INSN
    DW_CFA_max = 0xff
};

enum DW_LNCT {
#define DW_LNCT(name, value) name = value,
#include "libpstack/dwarf/line_ct.h"
#undef DW_LNCT
    DW_LNCT_max = 0xffff
};

enum DW_RLE {
#define DW_RLE(name, value) name = value,
#include "libpstack/dwarf/rle.h"
   DW_RLE_LAST
#undef DW_RLE
};

/*
 * A DWARF Reader is a wrapper for a reader that keeps a current position in the
 * underlying reader, and provides operations to read values in DWARF standard dwarf
 * encodings from the underlying reader, advancing the offset as it does so.
 */
class DWARFReader {
    Elf::Off off;
    Elf::Off end;
    uintmax_t getuleb128shift(int &shift, bool &msb);
public:
    ::Reader::csptr io;
    unsigned addrLen;

    DWARFReader(Reader::csptr io_, Elf::Off off_ = 0, size_t end_ = std::numeric_limits<size_t>::max())
        : off(off_)
        , end(end_ == std::numeric_limits<size_t>::max() ? io_->size() : end_)
        , io(std::move(io_))
        , addrLen(ELF_BITS / 8)
        {
        }

    void getBytes(size_t size, unsigned char *to) {
       io->readObj(off, to, size);
       off += size;
    }
    uint32_t getu32() {
        unsigned char q[4];
        io->readObj(off, q, 4);
        off += sizeof q;
        return q[0] | q[1] << 8 | q[2] << 16 | uint32_t(q[3] << 24);
    }
    uint16_t getu16() {
        unsigned char q[2];
        io->readObj(off, q, 2);
        off += sizeof q;
        return q[0] | q[1] << 8;
    }
    uint8_t getu8() {
        unsigned char q;
        io->readObj(off, &q, 1);
        off++;
        return q;
    }
    int8_t gets8() {
        int8_t q;
        io->readObj(off, &q, 1);
        off += 1;
        return q;
    }
    uintmax_t getuint(int len) {
        uintmax_t rc = 0;
        int i;
        uint8_t bytes[16];
        if (len > 16)
            throw Exception() << "can't deal with ints of size " << len;
        io->readObj(off, bytes, len);
        off += len;
        uint8_t *p = bytes + len;
        for (i = 1; i <= len; i++)
            rc = rc << 8 | p[-i];
        return rc;
    }
    intmax_t getint(int len) {
        intmax_t rc;
        int i;
        uint8_t bytes[16];
        if (len > 16 || len < 1)
            throw Exception() << "can't deal with ints of size " << len;
        io->readObj(off, bytes, len);
        off += len;
        uint8_t *p = bytes + len;
        rc = (p[-1] & 0x80) ? -1 : 0;
        for (i = 1; i <= len; i++)
            rc = rc << 8 | p[-i];
        return rc;
    }
    uintmax_t getuleb128() {
        int shift;
        bool msb;
        return getuleb128shift(shift, msb);
    }
    intmax_t getsleb128() {
        int shift;
        bool msb;
        intmax_t result = (intmax_t) getuleb128shift(shift, msb);
        // sign-extend the MSB to the rest of the intmax_t. Don't shift more
        // than the number of bits in intmax_t though!
        if (msb && shift < std::numeric_limits<intmax_t>::digits)
            result |= - ((uintmax_t)1 << shift);
        return result;
    }

    std::string readFormString(const Info *, const Unit *, Form f);
    void readForm(const Info *, const Unit *, Form f);
    uintmax_t readFormUnsigned(const Unit *, Form f);
    intmax_t readFormSigned(const Unit *, Form f);

    std::string getstring() {
        std::string s = io->readString(off);
        off += s.size() + 1;
        return s;
    }
    Elf::Off getOffset() const { return off; }
    Elf::Off getLimit() const { return end; }
    void setOffset(Elf::Off off_) {
       assert(end >= off_);
       off = off_;
    }
    bool empty() const {
       return off == end;
    }
    Elf::Off getlength(size_t *dwarfLen); // sets "dwarfLen"
    void skip(Elf::Off amount) { off += amount; }
};

struct MacroVisitor {
   virtual bool define(int, const std::string &) { return true; }
   virtual bool undef(int, const std::string &) { return true; }
   virtual bool startFile(int, const std::string &, const FileEntry &) { return true; }
   virtual bool endFile() { return true; }
};

std::string typeName(const DIE &);

DIE
findEntryForAddr(Elf::Addr address, Tag, const DIE &start);

inline
UnitIterator UnitIterator::operator ++() {
    currentUnit = currentUnit->end == info->io->size()
        ? nullptr
        : info->getUnit( currentUnit->end );
    return *this;
}

inline
UnitIterator Units::begin() const {
    return info->io ? iterator(info.get(), 0) : iterator();
}

inline
bool UnitIterator::atend() const {
    return currentUnit == nullptr;
}

inline
UnitIterator::UnitIterator(const Info *info_, Elf::Off offset)
    : info(info_), currentUnit(info->getUnit(offset)) {}



#define DWARF_OP(op, value, args) op = value,
enum ExpressionOp {
#include <libpstack/dwarf/ops.h>
    LASTOP = 0x100
};
#undef DWARF_OP

#define DW_EH_PE_absptr 0x00
#define DW_EH_PE_uleb128        0x01
#define DW_EH_PE_udata2 0x02
#define DW_EH_PE_udata4 0x03
#define DW_EH_PE_udata8 0x04
#define DW_EH_PE_sleb128        0x09
#define DW_EH_PE_sdata2 0x0A
#define DW_EH_PE_sdata4 0x0B
#define DW_EH_PE_sdata8 0x0C
#define DW_EH_PE_pcrel  0x10
#define DW_EH_PE_textrel        0x20
#define DW_EH_PE_datarel        0x30
#define DW_EH_PE_funcrel        0x40
#define DW_EH_PE_aligned        0x50
}
std::ostream &operator << (std::ostream &os, const JSON<Dwarf::Info> &);
std::ostream &operator << (std::ostream &os, const JSON<Dwarf::Macros> &);
std::ostream &operator << (std::ostream &os, const JSON<Dwarf::UnitType> &);

#endif
