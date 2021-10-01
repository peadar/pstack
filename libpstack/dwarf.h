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

// An entry in an abbrevation. Mostly a "form", but some forms have literal
// values associated with them.

struct FormEntry {
    Form form;
    intmax_t value;
    FormEntry(Form f, intmax_t v) : form(f), value(v) {}
};

// An abbreviation - the raw DIE info is a sequence of data items, each
// representing a dwarf attribute in a particular form. The Abbreviation
// associated with the DIE indicates the order of the attributes, and the form
// of each.
//
// Our interest in the attribute names is in order to find the index in the
// sequence associated with a particular attribute, which is what we store in
// attrName2Idx.
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

// An entry from a pubnames unit
struct Pubname {
    uint32_t offset;
    std::string name;
    Pubname(DWARFReader &r, uint32_t offset);
};

// The public names in a given unit.
struct PubnameUnit {
    uint16_t length;
    uint16_t version;
    uint32_t infoOffset;
    uint32_t infoLength;
    std::list<Pubname> pubnames;
    PubnameUnit(DWARFReader &r);
};

// Data stored in a BLOCK form attribute.
struct Block {
   Elf::Off offset;
   Elf::Off length;
};

// A generic value.
union Value {
    uintmax_t addr;
    uintmax_t signature;
    uintmax_t udata;
    intmax_t sdata;
    Block *block;
    bool flag;
};

// Iterable object for children of a DIE - as returned by DIE::children
class DIEChildren {
    const DIE &parent;
public:
    DIEChildren(const DIE &parent_) : parent(parent_) {}
    DIEIter begin() const;
    DIEIter end() const;
    using const_iterator = DIEIter;
    using value_type = DIE;
};

// A collection of attributes for a DIE, as returned by DIE::attributes
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

// An abstract "DIE" -
// A die exists in a tree within a unit. A die can be the rooot of a unit's tree, or
// a child, and may have children itself. "DIE" allows us access to this information.
//
// The abstract "DIE" wraps a "RawDIE" which is the raw data stored for that DIE
// in the debug_info section. The DIE augments it with references to its parent,
// unit, etc. (We are pasimonious with what we store with the raw DIE, as there can be
// a lot of them. "DIE" objects are not stored within the library, so are mostly
// temporary unless the API consumer keeps hold of them.

class DIE {

    friend DIEIter;
    friend Attribute;
    friend DIEAttributes;
    friend Unit;

    Elf::Off offset;
    std::shared_ptr<RawDIE> raw;
    std::shared_ptr<Unit> unit;

    // Decode the raw DIE Content at the given offset within the .debug_info
    // section for a particular unit.
    static std::shared_ptr<RawDIE> decode(Unit *unit, const DIE &parent, Elf::Off offset);

    // construct a DIE from its RawDIE, unit, and offset.
    DIE(const std::shared_ptr<Unit> &unit, size_t offset_, const std::shared_ptr<RawDIE> &raw)
        : offset(offset_)
        , raw(raw)
        , unit(unit)
        {}

public:

    // Indicate if the passed DIE contains code covering the passed address.
    // The result can be yes, no, or unknown.
    ContainsAddr containsAddress(Elf::Addr addr) const;

    // Return the offset (relative to the .debug_info section) of the parent DIE.
    Elf::Off getParentOffset() const;

    // Return the offset (relative to the .debug_info section) of this DIE
    Elf::Off getOffset() const { return offset; }

    const std::shared_ptr<Unit> &getUnit() const { return unit; }

    // Construct a "null" DIE.
    DIE()
        : offset(0)
        , raw(nullptr)
        , unit(nullptr)
        {}

    // The null die is false in a boolean context.
    operator bool() const { return raw != nullptr; }

    // Get the named attribute from thie DIE.
    Attribute attribute(AttrName name, bool local = false) const;

    std::string name() const;
    DIEAttributes attributes() const { return DIEAttributes(*this); }

    // Get the DIE's type tag.
    Tag tag() const;

    // Indicate if this DIE has any children.
    bool hasChildren() const;

    // Return the first child of this DIE.
    DIE firstChild() const;

    // Return the next sibling of this DIE.
    DIE nextSibling(const DIE &parent) const;

    // Get an iterator for all the children of this DIE.
    DIEChildren children() const { return DIEChildren(*this); }

    // Find the DIE covering a particular code address. If "skipInitial" is
    // false, then this DIE itself is not considered, only its decendents.  The
    // highest DIE in the tree is returned, so for inlined functions, etc, you
    // can repeat calls to findEntryForAddr with skipInitial true to find a
    // more nested DIE also covering the same address.
    DIE findEntryForAddr(Elf::Addr address, Tag, bool skipInitial = true);

    // Get a human-readable name for a type die - ascends through namespaces
    // that contain this DIE, walks through pointers and references, etc.
    std::string typeName(const DIE &);
};

// Ranges represents a sequence of addresses. The main use is to check if a text
// address exists in the range, and is therefore associated with some information,
// such as a location list, etc.
class Ranges : public std::vector<std::pair<uintmax_t, uintmax_t>> {
public:
   bool isNew { true };
};

// ARanges provides a fast way of finding the compilation unit associatd with a
// machine address. Note because not all compilers contribute to aranges, a
// miss on the aranges lookup does not mean there is no CU associated with the
// address, so we may augment this with our own manual scan of each unit.
using ARanges = std::map<Elf::Addr, std::pair<Elf::Addr, Elf::Off>>;

// An attribute within a DIE. A value that you can convert to one of a number
// of abstract types. The "form" provides information about the type.  We just
// sotre the DIE and the form entry for the attribute. The underlying data is
// retained in the raw DIE.
class Attribute {
    DIE dieref;
    const FormEntry *formp; /* From abbrev table attached to type */
    Value &value();
public:
    const DIE &die() const { return dieref; }
    const Value &value() const;
    Form form() const { return formp->form; }
    Attribute(const DIE &dieref_, const FormEntry *formp_)
       : dieref{dieref_}, formp{formp_} {}
    Attribute() : formp(nullptr) {}
    ~Attribute() { }

    bool valid() const { return formp != nullptr; }
    explicit operator std::string() const;
    explicit operator intmax_t() const;
    explicit operator uintmax_t() const;
    explicit operator bool() const { return valid() && value().flag; }
    explicit operator DIE() const;
    explicit operator const Block &() const { return *value().block; }
    explicit operator const Ranges &() const;
    AttrName name() const;
};

// .eh_frame and .debug_frame have subtly different internals, but are almost
// identical For when we need to discriminate, this is what we use.
enum FIType {
    FI_DEBUG_FRAME,
    FI_EH_FRAME
};

// A file entry associated with line number info. Mostly a name, and an index
// for the directory containing the file.
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
    void build(DWARFReader &, Unit &);
};

struct MacroVisitor;
// Summary of the macro section associated with a particular unit.
class Macros {
    bool visit5(Unit &, MacroVisitor *) const;
    bool visit4(Unit &, MacroVisitor *) const;
    void readD5(const Info &dwarf, intmax_t offset);
    void readD4(const Info &dwarf, intmax_t offset);
    int dwarflen;
    Reader::csptr io;
public:
    int debug_line_offset;
    uint16_t version;
    std::map<uint8_t, std::vector<uint8_t>> opcodes;
    Macros(const Info &info, intmax_t offset, int version);
    bool visit(Unit &, MacroVisitor *) const;
};

// A (partial-) compilation unit.
class Unit : public std::enable_shared_from_this<Unit> {

    using Abbreviations = std::unordered_map<size_t, Abbreviation>;

    // We store DIEs as their "raw" counterparts - when used by the API, we
    // return a DIE to wrap them. The DIE wrapper includes a reference to the
    // unit, the DIE's offset.
    //
    // Offsets here are relative to the debug_info section, rather than
    // the unit - this makes the offsets unique within the Info.
    using AllEntries = std::unordered_map<Elf::Off, std::shared_ptr<RawDIE>>;

    Unit() = delete;
    Unit(const Unit &) = delete;

    std::shared_ptr<RawDIE> offsetToRawDIE(const DIE &parent, Elf::Off offset);
    // Used to ensure abbreviations and other potentially expensive data is
    // parsed. Internals will call this to undo a "purge()"
    void load();

    Abbreviations abbreviations;
    AllEntries allEntries;
    Elf::Off rootOffset;
    Elf::Off abbrevOffset;
    std::unique_ptr<LineInfo> lines;
    std::unique_ptr<Macros> macros;
    UnitType unitType;

public:

    using sptr = std::shared_ptr<Unit>;
    using csptr = std::shared_ptr<const Unit>;
    using RangesForOffset = std::map<Elf::Addr, Ranges>;

    const Info *const dwarf; // back pointer to DWARF info

    // header fields
    const Elf::Off offset; // offset into debug_info
    const uint32_t length; // unit length
    const Elf::Off end; // a.k.a. start of next unit.
    const uint16_t version; // DWARF version

    size_t dwarfLen; // Size, as reported by DWARF length header.
    uint8_t addrlen; // size of addresses in this unit.
    unsigned char id[8]; // Unit ID for DWO.

    // Previously decoded ranges at a given offset in .debug_ranges / .debug_rnglists
    RangesForOffset rangesForOffset;

    Unit(const Info *, DWARFReader &);
    ~Unit();

    void purge(); // Remove all RawDIEs from allEntries, potentially freeing memory.

    // Is a given DIE the root for this unit?
    bool isRoot(const DIE &die) { return die.getOffset() == rootOffset; }

    DIE root(); // Get the root DIE for this unit

    // Given a (debug_info-relative) offset, return the DIE at that offset in this
    // unit. To convert from unit-relative offset, just subtract the unit's offset.
    DIE offsetToDIE(const DIE &parent, Elf::Off offset);

    std::string name(); // name from the root DIE.

    // Get line- and macro- information for this unit.
    const LineInfo *getLines();
    const Macros *getMacros();

    bool sourceFromAddr(Elf::Addr addr, std::vector<std::pair<std::string, int>> &info);
    const Abbreviation *findAbbreviation(size_t) const;
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

// Iterates over all units in an object. Existing units will be returned from the
// cache, and new units will be decoded and added.
struct Units {
    using value_type = Unit::sptr;
    using iterator = UnitIterator;
    using const_iterator = UnitIterator;
    const std::shared_ptr<const Info> info;
    UnitIterator begin() const;
    UnitIterator end() const { return iterator(); }
    Units(const std::shared_ptr<const Info> &info_) : info(info_) {}
};

// A frame-descriptor-entry describes the details of how to unwind the stack
// over a range of machine addresses to a caller.
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
    CFI(const Info *, Elf::Addr addr, Reader::csptr io, FIType);
    CFI() = delete;
    CFI(const CFI &) = delete;
    Elf::Addr decodeCIEFDEHdr(DWARFReader &, FIType, Elf::Off *cieOff); // cieOFF set to -1 if this is CIE, set to offset of associated CIE for an FDE
    const FDE *findFDE(Elf::Addr) const;
    bool isCIE(Elf::Addr);
    intmax_t decodeAddress(DWARFReader &, int encoding) const;
};

class ImageCache;

/*
 * Info represents all the interesting bits of the DWARF data.  Once
 * constructed, you can access DWARF compilation units, CFI information, macro
 * data, source information from here.
 */
class Info : public std::enable_shared_from_this<Info> {
public:
    using sptr = std::shared_ptr<Info>;
    using csptr = std::shared_ptr<const Info>;

    Info(Elf::Object::sptr, ImageCache &);
    ~Info();

    // Get a reference the the "alt" DWARF image, as pointed to by
    // ".gnu_debugaltlink"
    Info::sptr getAltDwarf() const;

    const std::list<PubnameUnit> &pubnames() const;

    // get a unit, given an offset.
    Unit::sptr getUnit(Elf::Off offset) const;

    // Iterate over all units in the ELF object.
    Units getUnits() const;

    // Given a debug_info-relative offset, find the associated DIE.
    DIE offsetToDIE(Elf::Off) const;

    // Find the unit covering a given (object-relative) text address.
    // Will use debug_aranges where possible.
    Unit::sptr lookupUnit(Elf::Addr addr) const;
    std::vector<std::pair<std::string, int>> sourceFromAddr(uintmax_t addr) const;
    LineInfo *linesAt(intmax_t, Unit &) const;

    // The ELF object this DWARF data is associated with
    const Elf::Object::sptr elf;

    // Cached call frames for specific return addresses.
    std::map<Elf::Addr, CallFrame> callFrameForAddr;

    // Get decoded call frame information from .debug_frame section
    CFI *getDebugFrame() const;

    // Get decoded call frame information from .eh_frame section
    CFI *getEhFrame() const;

    // direct access to various DWARF sections.
    const Reader::csptr debugInfo;
    const Reader::csptr debugStrings;
    const Reader::csptr debugLineStrings;
    const Reader::csptr debugRanges;
    const Reader::csptr debugStrOffsets;

    // For _strx forms, indirect through debugStrOffsets to get a string for a
    // specific index.
    std::string strx(Unit &unit, size_t idx) const;

private:
    ImageCache &imageCache;
    std::unique_ptr<CFI> decodeCFI(const char *name, const char *zname, FIType ftype) const;

    // These are mutable so we can lazy-eval them when getters are called, and
    // maintain logical constness.
    mutable std::unique_ptr<std::list<PubnameUnit>> pubnameUnits { nullptr };
    mutable std::map<Elf::Off, Unit::sptr> units;
    mutable Info::sptr altDwarf;
    mutable std::unique_ptr<ARanges> aranges; // maps starting address to length + unit offset.
    mutable std::unique_ptr<Macros> macros;
    mutable std::unique_ptr<CFI> debugFrame;
    mutable std::unique_ptr<CFI> ehFrame;

    mutable bool altImageLoaded { false };
    mutable bool unitRangesCached { false };
    mutable bool debugFrameLoaded { false };
    mutable bool ehFrameLoaded = { false };

    void decodeARangeSet(DWARFReader &) const;
    std::string getAltImageName() const;
};

/*
 * A Dwarf Image Cache is an (Elf) ImageCache, but caches Dwarf::Info for the
 * Objects also. (see elf.h:ImageCache)
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

/* Iterator for direct children of a parent DIE, as returned by DIEChildren::begin() */
class DIEIter {
    const std::shared_ptr<const Unit> u;
    const DIE parent;
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
            currentDIE.getOffset() == rhs.currentDIE.getOffset();
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
 * underlying reader, and provides operations to read values in DWARF standard
 * encodings, advancing the offset as it does so.
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

    std::string readFormString(const Info &, Unit &, Form f);
    void readForm(const Info &, Unit &, Form f);
    uintmax_t readFormUnsigned(Unit &, Form f);
    intmax_t readFormSigned(Unit &, Form f);

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

inline
UnitIterator UnitIterator::operator ++() {
    currentUnit = currentUnit->end == info->debugInfo->size()
        ? nullptr
        : info->getUnit( currentUnit->end );
    return *this;
}

inline
UnitIterator Units::begin() const {
    return info->debugInfo ? iterator(info.get(), 0) : iterator();
}

inline bool
UnitIterator::atend() const {
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
