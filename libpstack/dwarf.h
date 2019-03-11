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

#include <cassert>

namespace Dwarf {

enum HasChildren { DW_CHILDREN_yes = 1, DW_CHILDREN_no = 0 };

class Attribute;
class RawDIE;
class ExpressionStack;
class Info;
class LineInfo;
class DWARFReader;
class DIE;
struct CIE;
struct CFI;
class Unit;

typedef std::vector<size_t> Entries;

#define DWARF_TAG(a,b) a = b,
enum Tag {
#include <libpstack/dwarf/tags.h>
    DW_TAG_none = 0x0
};
#undef DWARF_ATE

#define DWARF_ATE(a,b) a = b,
enum Encoding {
#include <libpstack/dwarf/encodings.h>
    DW_ATE_none = 0x0
};
#undef DWARF_TAG

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

struct Abbreviation {
    Tag tag;
    bool hasChildren;
    std::vector<Form> forms;
    using AttrNameMap = std::unordered_map<AttrName, size_t>;
    AttrNameMap attrName2Idx;
    Abbreviation(DWARFReader &);
    Abbreviation() {}
};

struct Pubname {
    uint32_t offset;
    std::string name;
    Pubname(DWARFReader &r, uint32_t offset);
};

struct ARange {
    uintmax_t start;
    uintmax_t length;
    ARange(uintmax_t start_, uintmax_t length_) : start(start_), length(length_) {}
};

struct ARangeSet {
    uint32_t length;
    uint16_t version;
    uint32_t debugInfoOffset;
    uint8_t addrlen;
    uint8_t segdesclen;
    std::vector<ARange> ranges;
    ARangeSet(DWARFReader &r);
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
    off_t offset;
    off_t length;
};

union Value {
    uintmax_t addr;
    uintmax_t udata;
    intmax_t sdata;
    Block *block;
    bool flag;
};


struct DIEIter {
    const Unit *u;
    Entries::const_iterator rawIter;
    DIE operator *() const;
    DIEIter &operator++() {
        ++rawIter;
        return *this;
    }
    DIEIter(const Unit *unit_, Entries::const_iterator rawIter_) :
        u(unit_), rawIter(rawIter_) {}
    bool operator == (const DIEIter &rhs) const {
        return rawIter == rhs.rawIter;
    }
    bool operator != (const DIEIter &rhs) const {
        return rawIter != rhs.rawIter;
    }
};

struct DIEList {
    using const_iterator = DIEIter;
    using value_type = DIE;
    const Unit *unit;
    const Entries &dies;
    DIEIter begin() const;
    DIEIter end() const;
    DIEList(const Unit *unit_, const Entries &dies_)
        : unit(unit_), dies(dies_) {}
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

class DIE {
    const Unit *unit;
    off_t offset;
    const RawDIE *die;
    friend class Attribute;
    friend class DIEAttributes;
public:
    off_t getParentOffset() const;
    off_t getOffset() const { return offset; }
    const Unit *getUnit() const { return unit; }
    DIE(const Unit *unit, size_t offset_, const RawDIE *die) : unit(unit), offset(offset_), die(die) {}
    DIE() : unit(nullptr) {}
    operator bool() const { return unit != nullptr; }
    bool hasChildren() const;
    Attribute attribute(AttrName name) const;
    inline std::string name() const;
    DIEList children() const;
    DIEAttributes attributes() const { return DIEAttributes(*this); }
    Tag tag() const;
};

class Attribute {
    DIE dieref;
    const Form *formp; /* From abbrev table attached to type */

    Value &value();
public:
    const DIE &die() const { return dieref; }
    const Value &value() const;
    Form form() const { return *formp; }
    Attribute(const DIE &dieref_, const Form *formp_)
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
    FileEntry() = delete;
    // copy-constructable.
public:
    std::string name;
    std::string directory;
    unsigned lastMod;
    unsigned length;
    FileEntry(std::string name_, std::string dir_, unsigned lastMod_, unsigned length_);
    FileEntry(DWARFReader &r, LineInfo *info);
};

class LineState {
    LineState() = delete;
public:
    uintmax_t addr;
    const FileEntry *file;
    unsigned line;
    unsigned column;
    unsigned isa;
    bool is_stmt:1;
    bool basic_block:1;
    bool end_sequence:1;
    bool prologue_end:1;
    bool epilogue_begin:1;
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

class RawDIE {
    RawDIE() = delete;
    RawDIE(const RawDIE &) = delete;
    static void readValue(DWARFReader &, Form form, Value &value, const Unit *);
    Entries children;
    const Abbreviation *type;
    std::vector<Value> values;
    off_t parent;
public:
    RawDIE(DWARFReader &, size_t, Unit *, off_t self, off_t parent);
    ~RawDIE();
    friend class Attribute;
    friend class DIE;
    friend class DIEAttributes;
};

class Unit {
    Unit() = delete;
    Unit(const Unit &) = delete;
    std::unique_ptr<LineInfo> lines;
    std::unordered_map<size_t, Abbreviation> abbreviations;
    Entries entries;
    std::unordered_map<off_t, RawDIE> allEntries;
public:
    const Abbreviation *findAbbreviation(size_t) const;
    DIEList topLevelDIEs() const { return DIEList(this, entries); }
    DIE offsetToDIE(size_t offset) const;
    const Info *dwarf;
    Reader::csptr io;
    off_t offset;
    size_t dwarfLen;
    void decodeEntries(DWARFReader &r, Entries &entries, off_t parent);
    uint32_t length;
    uint16_t version;
    uint8_t addrlen;
    Unit(const Info *, DWARFReader &);
    std::string name() const;
    const LineInfo *getLines();
    ~Unit();
    typedef std::shared_ptr<Unit> sptr;
    typedef std::shared_ptr<const Unit> csptr;
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
    Elf::Word sectionAddr; // virtual address of this section  (may need to be offset by load address)
    Reader::csptr io;
    FIType type;
    std::map<Elf::Addr, CIE> cies;
    std::list<FDE> fdeList;
    CFI(Info *, Elf::Word addr, Reader::csptr io, FIType);
    CFI() = delete;
    CFI(const CFI &) = delete;
    Elf::Addr decodeCIEFDEHdr(DWARFReader &, FIType, Elf::Off *cieOff); // cieOFF set to -1 if this is CIE, set to offset of associated CIE for an FDE
    const FDE *findFDE(Elf::Addr) const;
    bool isCIE(Elf::Addr);
    intmax_t decodeAddress(DWARFReader &, int encoding) const;
};

class ImageCache;
/*
 * Info represents all the interesting bits of the DWARF data.
 */
class Info {
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
    Reader::csptr abbrev;
    Reader::csptr lineshdr;
    Info::sptr getAltDwarf() const;
    std::list<ARangeSet> &getARanges() const;
    const std::list<PubnameUnit> &pubnames() const;
    Unit::sptr getUnit(off_t offset);
    const std::list<Unit::sptr> &getUnits() const;
    std::vector<std::pair<std::string, int>> sourceFromAddr(uintmax_t addr);
    bool hasARanges() { getARanges(); return aranges.size() != 0; }

private:
    std::string getAltImageName() const;
    mutable std::list<PubnameUnit> pubnameUnits;
    mutable std::list<ARangeSet> aranges;
    // These are mutable so we can lazy-eval them when getters are called, and
    // maintain logical constness.
    mutable std::list<Unit::sptr> allUnits;
    mutable std::map<Elf::Off, Unit::sptr> unitsm;
    mutable Info::sptr altDwarf;
    mutable bool haveAllUnits;
    mutable bool altImageLoaded;
    ImageCache &imageCache;
    mutable Reader::csptr pubnamesh;
    mutable Reader::csptr arangesh;
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

enum CFAInstruction {
#define DWARF_CFA_INSN(name, value) name = value,
#include "libpstack/dwarf/cfainsns.h"
#undef DWARF_CFA_INSN
    DW_CFA_max = 0xff
};

/*
 * A DWARF Reader is a wrapper for a reader that keeps a current position in the
 * underlying reader, and provides operations to read values in DWARF standard dwarf
 * encodings from the underlying reader, advancing the offset as it does so.
 */
class DWARFReader {
    Elf::Off off;
    Elf::Off end;
    uintmax_t getuleb128shift(int *shift, bool &isSigned);
public:
    ::Reader::csptr io;
    unsigned addrLen;

    DWARFReader(Reader::csptr io_, Elf::Off off_ = 0, size_t end_ = std::numeric_limits<size_t>::max())
        : off(off_)
        , end(end_ == std::numeric_limits<size_t>::max() ? io_->size() : end_)
        , io(std::move(io_))
        , addrLen(ELF_BITS / 8) {
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
        bool isSigned;
        return getuleb128shift(&shift, isSigned);
    }
    intmax_t getsleb128() {
        int shift;
        bool isSigned;
        intmax_t result = (intmax_t) getuleb128shift(&shift, isSigned);
        if (isSigned)
            result |= - ((uintmax_t)1 << shift);
        return result;
    }

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
    Elf::Off getlength(size_t *);
    void skip(Elf::Off amount) { off += amount; }
};

std::string typeName(const DIE &);
DIE findEntryForFunc(Elf::Addr address, const DIE &entry);


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

#endif
