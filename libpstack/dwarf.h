#ifndef DWARF_H
#define DWARF_H

#include "libpstack/elf.h"
#include <list>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <iterator>

namespace pstack::Dwarf {

enum HasChildren { DW_CHILDREN_yes = 1, DW_CHILDREN_no = 0 };
class DIE;
class DWARFReader;
class Info;
class LineInfo;
class Unit;
class CFI;
struct CIE;
}

namespace pstack {

std::ostream & operator << (std::ostream &os, const JSON<pstack::Dwarf::CFI> &);

namespace Dwarf {

#define DWARF_TAG(a,b) a = (b),
enum Tag {
#include "libpstack/dwarf/tags.h"
    DW_TAG_none = 0x0
};
#undef DWARF_TAG

#define DWARF_ATE(a,b) a = (b),
enum Encoding {
#include "libpstack/dwarf/encodings.h"
    DW_ATE_none = 0x0
};
#undef DWARF_ATE

#define DWARF_UNIT_TYPE(a,b) a = (b),
enum UnitType {
#include "libpstack/dwarf/unittype.h"
    DW_UT_none
};
#undef DWARF_UNIT_TYPE

#define DWARF_FORM(a,b) a = (b),
enum Form {
#include "libpstack/dwarf/forms.h"
    DW_FORM_none = 0x0
};
#undef DWARF_FORM

#define DWARF_ATTR(a,b) a = (b),
enum AttrName {
#include "libpstack/dwarf/attr.h"
    DW_AT_none = 0x0
};

} // Dwarf

} // pstack
namespace std {
   template <> struct hash<pstack::Dwarf::AttrName> {
      size_t operator() (pstack::Dwarf::AttrName name) const { return size_t(name); }
   };
}

namespace pstack {
namespace Dwarf {

#define DWARF_OP(op, value, args) op = (value),
enum ExpressionOp {
#include "libpstack/dwarf/ops.h"
    LASTOP = 0x100
};
#undef DWARF_OP

#define DWARF_EH_PE(op, value) op = (value),
enum ExceptionHandlingEncoding {
#include "libpstack/dwarf/ehpe.h"
    DW_EH_PE_max
};

#undef DWARF_ATTR

#define DWARF_LINE_S(a,b) a = (b),
enum LineSOpcode {
#include "libpstack/dwarf/line_s.h"
    DW_LNS_none = -1
};
#undef DWARF_LINE_S

#define DWARF_LINE_E(a,b) a = (b),
enum LineEOpcode {
#include "libpstack/dwarf/line_e.h"
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
    mutable bool sorted;
    std::vector<FormEntry> forms;
    using AttrNameEnt = std::pair<AttrName, size_t>;
    using AttrNameMap = std::vector<AttrNameEnt>;
    int nextSibIdx;
    mutable AttrNameMap attrName2Idx; // mutable so we can sort on demand
    explicit Abbreviation(DWARFReader &);
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
    explicit PubnameUnit(DWARFReader &r);
};

// Data stored in a BLOCK form attribute.
struct Block {
   Elf::Off offset;
   Elf::Off length;
};

enum class ContainsAddr { YES, NO, UNKNOWN };

// Ranges represents a sequence of addresses. The main use is to check if a text
// address exists in the range, and is therefore associated with some information,
// such as a location list, etc.
class Ranges : public std::vector<std::pair<uintmax_t, uintmax_t>> {
   public:
      Ranges(const DIE &, uintmax_t base);
};

// An abstract "DIE" -
// A die exists in a tree within a unit. A die can be the rooot of a unit's tree, or
// a child, and may have children itself. "DIE" allows us access to this information.
//
// The abstract "DIE" wraps a "DIE::Raw" which is the raw data stored for that DIE
// in the debug_info section. The DIE augments it with references to its parent,
// unit, etc. (We are pasimonious with what we store with the raw DIE, as there can be
// a lot of them. "DIE" objects are not stored within the library, so are mostly
// temporary unless the API consumer keeps hold of them.
class DIE {

    // DIEs are only constructed by units: hide constructors from everyone else.
    friend Unit;

    Elf::Off offset{};
    class Raw;

    std::shared_ptr<Raw> raw;
    std::shared_ptr<Unit> unit;

    // construct a DIE from its "Raw" DIE, unit, and offset.
    DIE(const std::shared_ptr<Unit> &unit, size_t offset_, const std::shared_ptr<Raw> &raw)
        : offset(offset_)
        , raw(raw)
        , unit(unit)
        {}

    // Decode the raw DIE Content at the given offset within the .debug_info
    // section for a particular unit.
    static std::shared_ptr<Raw> decode(Unit *unit, const DIE &parent, Elf::Off offset);

    // Return the first child of this DIE (used by iterator implementation)
    [[nodiscard]] DIE firstChild() const;

    // Return the next sibling of this DIE (used by iterator implementation
    [[nodiscard]] DIE nextSibling(const DIE &parent) const;


public:
    class Attribute;
    const static DIE null;

    // A collection of attributes for a DIE, as returned by DIE::attributes
    class Attributes {
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
        [[nodiscard]] const_iterator begin() const;
        [[nodiscard]] const_iterator end() const;
        explicit Attributes(const DIE &die) : die(die) {}
    };

    // Iterable object for children of a DIE - as returned by children()
    class Children {
        const DIE &parent;
    public:
        class const_iterator;
        explicit Children(const DIE &parent_) : parent(parent_) {}
        [[nodiscard]] const_iterator begin() const;
        [[nodiscard]] const_iterator end() const;
        using value_type = DIE;
    };

    // Indicate if the passed DIE contains code covering the passed address.
    // The result can be yes, no, or unknown.
    [[nodiscard]] ContainsAddr containsAddress(Elf::Addr addr) const;

    // Return the offset (relative to the .debug_info section) of the parent DIE.
    [[nodiscard]] Elf::Off getParentOffset() const;

    // Return the offset (relative to the .debug_info section) of this DIE
    [[nodiscard]] Elf::Off getOffset() const { return offset; }

    [[nodiscard]] const std::shared_ptr<Unit> &getUnit() const { return unit; }

    // The null die is false in a boolean context.
    explicit operator bool() const { return raw != nullptr; }

    // Get the named attribute from thie DIE.
    [[nodiscard]] Attribute attribute(AttrName name, bool local = false) const;

    [[nodiscard]] std::string name() const;
    [[nodiscard]] Attributes attributes() const { return Attributes(*this); }

    // Get the DIE's type tag.
    [[nodiscard]] Tag tag() const;

    // Indicate if this DIE has any children.
    [[nodiscard]] bool hasChildren() const;

    // Get an iterator for all the children of this DIE.
    [[nodiscard]] Children children() const { return Children(*this); }

    // Find the DIE covering a particular code address. If "skipInitial" is
    // false, then this DIE itself is not considered, only its decendents.  The
    // highest DIE in the tree is returned, so for inlined functions, etc, you
    // can repeat calls to findEntryForAddr with skipInitial true to find a
    // more nested DIE also covering the same address.
    DIE findEntryForAddr(Elf::Addr address, Tag, bool skipInitial = true);

    // Get a human-readable name for a type die - ascends through namespaces
    // that contain this DIE, walks through pointers and references, etc.
    [[nodiscard]] std::string typeName();
    [[nodiscard]] const std::unique_ptr<Ranges> &getRanges() const;

    DIE() = default;
    DIE(const DIE &) = default;
    DIE(DIE &&) = default;
    DIE &operator = (const DIE &) = default;
    DIE &operator = (DIE &&) = default;
    ~DIE() = default;
};

// ARanges provides a fast way of finding the compilation unit associatd with a
// machine address. Note because not all compilers contribute to aranges, a
// miss on the aranges lookup does not mean there is no CU associated with the
// address, so we may augment this with our own manual scan of each unit.
using ARanges = std::map<Elf::Addr, std::pair<Elf::Addr, Elf::Off>>;

// .eh_frame and .debug_frame have subtly different internals, but are almost
// identical For when we need to discriminate, this is what we use.
enum FIType {
    FI_DEBUG_FRAME,
    FI_EH_FRAME,
    FI_BEST,
};

// A file entry associated with line number info. Mostly a name, and an index
// for the directory containing the file.
class FileEntry {
public:

    FileEntry() = default;

    FileEntry(const FileEntry &) = default;
    FileEntry(FileEntry &&) = default;
    FileEntry &operator = (const FileEntry &) = default;
    FileEntry &operator = (FileEntry &&) = default;
    ~FileEntry() = default;

    std::string name;
    unsigned dirindex{};
    unsigned lastMod{};
    unsigned length{};
    FileEntry(std::string name_, unsigned dirindex, unsigned lastMod_, unsigned length_);
    explicit FileEntry(DWARFReader &r);
};

class LineState {
public:
    LineState() = delete;
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
    explicit LineState(LineInfo *);
};

class LineInfo {
public:
    LineInfo(const LineInfo &) = delete;
    LineInfo(LineInfo &&) = delete;
    LineInfo &operator = (const LineInfo &) = delete;
    LineInfo &operator = (LineInfo &&) = delete;
    LineInfo() = default;
    ~LineInfo() = default;

    bool default_is_stmt = false;
    uint8_t opcode_base = 0;
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
    using AllEntries = std::map<Elf::Off, std::shared_ptr<DIE::Raw>>;

    std::shared_ptr<DIE::Raw> offsetToRawDIE(const DIE &parent, Elf::Off offset);
    // Used to ensure abbreviations and other potentially expensive data is
    // parsed. Internals will call this to undo a "purge()"
    void load();

    Abbreviations abbreviations;
    AllEntries allEntries;
    Elf::Off rootOffset;
    Elf::Off abbrevOffset;
    std::unique_ptr<LineInfo> lines;
    std::unique_ptr<Macros> macros;

    // Previously decoded ranges at a given offset in .debug_ranges / .debug_rnglists
    using RangesForOffset = std::map<Elf::Addr, std::unique_ptr<Ranges>>;
    RangesForOffset rangesForOffset;

public:

    Unit() = delete;
    Unit(const Unit &) = delete;
    Unit(Unit &&) = delete;
    Unit &operator = (const Unit &) = delete;
    Unit &operator = (Unit &&) = delete;
    ~Unit() noexcept = default;

    using sptr = std::shared_ptr<Unit>;
    using csptr = std::shared_ptr<const Unit>;

    const std::unique_ptr<Ranges> &getRanges(const DIE &die, uintmax_t base);

    const Info *const dwarf; // back pointer to DWARF info

    // header fields
    UnitType unitType;
    Elf::Off offset; // offset into debug_info
    uint32_t length; // unit length
    Elf::Off end; // a.k.a. start of next unit.
    uint16_t version; // DWARF version

    size_t dwarfLen; // Size, as reported by DWARF length header.
    uint8_t addrlen; // size of addresses in this unit.
    std::array<unsigned char, 8> id; // Unit ID for DWO.

    Unit(const Info *, DWARFReader &);

    void purge(); // Remove all "raw" DIEs from allEntries, potentially freeing memory.

    // Is a given DIE the root for this unit?
    [[nodiscard]] bool isRoot(const DIE &die) const {
        return die.getOffset() == rootOffset;
    }

    // Get the root DIE for this unit
    DIE root();

    // Given a (debug_info-relative) offset, return the DIE at that offset in this
    // unit. To convert from unit-relative offset, just subtract the unit's offset.
    DIE offsetToDIE(const DIE &parent, Elf::Off offset);

    std::string name(); // name from the root DIE.

    // Get line- and macro- information for this unit.
    const std::unique_ptr<LineInfo> &getLines();
    const Macros *getMacros();

    bool sourceFromAddr(Elf::Addr addr, std::vector<std::pair<std::string, int>> &info);
    const Abbreviation *findAbbreviation(size_t) const;

    // For _strx forms, indirect through debugStrOffsets to get a string for a
    // specific index.
    std::string strx(size_t idx);

    // addrx forms are similar - indirect through table in .debug_addr.
    uintmax_t addrx(size_t idx);

    // rnglistx again similar, but more convoluted.
    uintmax_t rnglistx(size_t idx);

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
    FDE(const CFI &, DWARFReader &, Elf::Off cieOff_, Elf::Off endOff_);
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

// A regiser unwind indicates how to restore the state of a register in the
// calling frame
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

// A "CallFrame" represents the unwind information for a particular address -
// it is the result of execting the location instructions in the FDE and CIE
// to a specific address.
struct CallFrame {
    std::map<int, RegisterUnwind> registers;
    int cfaReg;
    RegisterUnwind cfaValue;
    CallFrame();
    // default copy constructor is valid.
};

// A CIE is a Common Information Entry, describing attributes of code and some
// initial location instructions potentially shared by multiple FDEs
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
    std::pair<uintmax_t,bool> personality;
    std::string augmentation;
    CIE(const CFI *, DWARFReader &, Elf::Off);
    CIE() = default;
    CallFrame execInsns(DWARFReader &r, uintmax_t addr, uintmax_t wantAddr) const;
};

/*
 * CFI represents call frame information (generally contents of .debug_frame or .eh_frame)
 */
class CFI {
public:
    using CIEs = std::map<Elf::Addr, CIE>;
    using FDEs = std::vector<std::unique_ptr<FDE>>;
    [[nodiscard]] const CIE &getCIE(Elf::Addr off) const { return cies.at(off); }
    [[nodiscard]] const CIEs &getCIEs() const;
    [[nodiscard]] const FDEs &getFDEs() const;
    [[nodiscard]] const FDE *findFDE(Elf::Addr) const;
    [[nodiscard]] operator bool() const noexcept { return io != nullptr; }

    CFI(const Info *, FIType);
    CFI() = delete;
    CFI(const CFI &) = delete;
    CFI(CFI &&) = delete;
    CFI &operator = (const CFI &) = delete;
    CFI &operator = (CFI &&) = delete;
    ~CFI() = default;

    Reader::csptr io; // public to allow decoding instructions.
private:
    friend struct FDE;
    friend struct CIE;
    const Info *dwarf;
    Elf::Addr sectionAddr; // virtual address of section (either eh_frame or debug_frame.
    Elf::Addr ehFrameHdrAddr; // virtual address of eh_frame_hdr
    FIType type;
    mutable CIEs cies;

    // FDEs are sorted by their iloc field. If we have an fdeTable, then the
    // table starts out with the correct size, but unpopulated, and searching
    // for an FDE will lazily populate it from the fdeTable If the ELF object
    // contains no eh_frame_hdr section, then we read the entire eh_frame
    // section when we first construct the CFI object, and prepopulate this
    // with al the FDEs. Currently, this happens for the VDSO in aarch64
    // platforms (where there are just a handful of FDEs), and pretty much
    // everything else has an eh_frame_hdr.
    mutable FDEs fdes;

    ExceptionHandlingEncoding fdeTableEnc; // the encoding format of the entries in fdeTable.
    mutable Reader::csptr fdeTable; // the start of the table in the eh_frame_hdr section.
    std::pair<bool, std::unique_ptr<FDE>> putFDEorCIE( DWARFReader &reader ) const;

    // cieOFF set to -1 if this is CIE, set to offset of associated CIE for an FDE
    Elf::Addr decodeCIEFDEHdr(DWARFReader &, FIType, Elf::Off *cieOff) const;
    bool isCIE(Elf::Addr) const noexcept;
    //void putCIE(DWARFReader &r); // Put CIE from current offset.
    void putCIE(Elf::Addr offset, DWARFReader &r, Elf::Addr end) const; // put CIE who's header we already decoded.

    std::pair<uintmax_t, bool> decodeAddress(DWARFReader &, uint8_t encoding, uintptr_t sectionVa) const;

    void ensureFDE(size_t idx) const; // ensures that the fde at index idx is preloaded.
    void ensureFDEs() const; // ensure all FDEs are pre-loaded.
};

// Iterates over all units in an object. Existing units will be returned from the
// cache, and new units will be decoded and added.
struct Units {
    class iterator {
        const Info *info;
        Unit::sptr currentUnit;
        [[nodiscard]] bool atend() const;
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = Unit::sptr;
        using difference_type = int;
        using pointer = Unit::sptr *;
        using reference = Unit::sptr &;
        Unit::sptr operator *() { return currentUnit; }
        iterator operator ++();
        bool operator == (const iterator &rhs) const {
            if (atend() || rhs.atend())
                return atend() == rhs.atend();
            return info == rhs.info && currentUnit->offset == rhs.currentUnit->offset;
        }
        bool operator != (const iterator &rhs) const {
            return !(*this == rhs);
        }
        iterator(const Info *info_, Elf::Off offset);
        iterator() : info(nullptr), currentUnit(nullptr) {}
    };
    using value_type = Unit::sptr;
    using const_iterator = iterator;
    const std::shared_ptr<const Info> info;
    [[nodiscard]] iterator begin() const;
    [[nodiscard]] iterator end() const { (void)this; return {}; }
    explicit Units(const std::shared_ptr<const Info> &info_) : info(info_) {
    }
};

/*
 * Info represents all the interesting bits of the DWARF data.  Once
 * constructed, you can access DWARF compilation units, CFI information, macro
 * data, source information from here.
 */
class Info : public std::enable_shared_from_this<Info> {
public:
    using sptr = std::shared_ptr<Info>;
    using csptr = std::shared_ptr<const Info>;

    Info(Elf::Object::sptr);

    Info() = delete;
    Info(const Info &) = delete;
    Info(Info &&) = delete;
    Info &operator = (Info && ) = delete;
    Info &operator = (const Info & ) = delete;

    ~Info() noexcept = default;

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

    // Find the source associated with a specific address. Due to inlining and
    // optimization, there may be more than one functions for the specific
    // address.
    std::vector<std::pair<std::string, int>> sourceFromAddr(uintmax_t addr) const;

    std::unique_ptr<LineInfo> linesAt(intmax_t, Unit &) const;

    // The ELF object this DWARF data is associated with
    const Elf::Object::sptr elf;

    // Cached call frames for specific return addresses.
    std::map<Elf::Addr, CallFrame> callFrameForAddr;

    CFI *getCFI(FIType = FI_BEST) const;

    // direct access to various DWARF sections.
    const Elf::Section & debugInfo;
    const Elf::Section & debugStrings;
    const Elf::Section & debugLineStrings;
    const Elf::Section & debugRanges;
    const Elf::Section & debugStrOffsets;
    const Elf::Section & debugAddr;
    const Elf::Section & debugRangelists;
private:
    std::unique_ptr<CFI> decodeCFI(const Elf::Section &, FIType ftype, Reader::csptr) const;

    // These are mutable so we can lazy-eval them when getters are called, and
    // maintain logical constness.
    mutable std::unique_ptr<std::list<PubnameUnit>> pubnameUnits { nullptr };
    mutable std::map<Elf::Off, Unit::sptr> units;
    mutable Info::sptr altDwarf;
    mutable std::unique_ptr<ARanges> aranges; // maps starting address to length + unit offset.
    mutable std::unique_ptr<Macros> macros;
    mutable std::map<FIType, std::unique_ptr<CFI>> cfi;

    mutable bool altImageLoaded { false };
    mutable bool unitRangesCached { false };

    void decodeARangeSet(DWARFReader &) const;
    std::string getAltImageName() const;
};

// An attribute within a DIE. A value that you can convert to one of a number
// of abstract types. The "form" provides information about the type.  We just
// sotre the DIE and the form entry for the attribute. The underlying data is
// retained in the raw DIE.
class DIE::Attribute {
    friend class DIE::Raw;
    // A generic value.
    union Value {
        Value(DWARFReader &, const FormEntry &form, Unit *);
        uintmax_t addr;
        uintmax_t signature;
        uintmax_t udata;
        intmax_t sdata;
        Block *block;
        bool flag;
    };
public:
    [[nodiscard]] const Value &value() const;
    [[nodiscard]] Form form() const { return formp->form; }
    explicit Attribute(DIE dieref_, const FormEntry *formp_)
       : die{std::move(dieref_)}, formp{formp_} {}
    Attribute() noexcept : die(), formp(nullptr) {}
    ~Attribute() noexcept = default;
    Attribute(const Attribute &) = delete;
    Attribute(Attribute &&) = default;
    Attribute &operator = (const Attribute &) = delete;
    Attribute &operator = (Attribute &&) = delete;

    [[nodiscard]] bool valid() const { return formp != nullptr; }
    explicit operator std::string() const;
    explicit operator intmax_t() const;
    explicit operator uintmax_t() const;
    explicit operator bool() const { return valid() && value().flag; }
    explicit operator DIE() const;
    explicit operator const Block &() const { return *value().block; }
    [[nodiscard]] AttrName name() const;
    const DIE die;

private:
    const FormEntry *formp; /* From abbrev table attached to type */
    Value &value();
};

/* Iterator for direct children of a parent DIE, as returned by DIE::Children::begin() */
class DIE::Children::const_iterator {
    friend DIE::Children;
    const std::shared_ptr<const Unit> u;
    const DIE parent;
    DIE currentDIE;
    const_iterator(const DIE &first, const DIE & parent_);
public:
    const DIE &operator *() const { return currentDIE; }
    const_iterator &operator++();
    bool operator == (const const_iterator &rhs) const {
        if (!currentDIE)
            return !rhs.currentDIE;
        if (!rhs.currentDIE)
            return false;
        return currentDIE.unit == rhs.currentDIE.unit &&
            currentDIE.getOffset() == rhs.currentDIE.getOffset();
    }
    bool operator != (const const_iterator &rhs) const { return !(*this == rhs); }
};

enum CFAInstruction {
#define DWARF_CFA_INSN(name, value) name = (value),
#include "libpstack/dwarf/cfainsns.h"
#undef DWARF_CFA_INSN
    DW_CFA_max = 0xff
};

enum DW_LNCT {
#define DW_LNCT(name, value) name = (value),
#include "libpstack/dwarf/line_ct.h"
#undef DW_LNCT
    DW_LNCT_max = 0xffff
};

enum DW_RLE {
#define DW_RLE(name, value) name = (value),
#include "libpstack/dwarf/rle.h"
   DW_RLE_LAST
#undef DW_RLE
};

struct MacroVisitor {
   virtual bool define([[maybe_unused]] int line, [[maybe_unused]] const std::string &text) { return true; }
   virtual bool undef([[maybe_unused]] int line, [[maybe_unused]] const std::string &text) { return true; }
   virtual bool startFile([[maybe_unused]] int line, [[maybe_unused]] const std::string &directory, [[maybe_unused]] const FileEntry &fileInfo) { return true; }
   virtual bool endFile() { return true; }

   MacroVisitor() = default;
   MacroVisitor(const MacroVisitor &) = default;
   MacroVisitor(MacroVisitor &&) = default;
   MacroVisitor &operator = (const MacroVisitor &) = default;
   MacroVisitor &operator = (MacroVisitor &&) = default;
   virtual ~MacroVisitor() = default;
};

inline
Units::iterator Units::iterator::operator ++() {
    currentUnit = currentUnit->end == info->debugInfo.io()->size()
        ? nullptr
        : info->getUnit( currentUnit->end );
    return *this;
}

inline
Units::iterator Units::begin() const {
    return info->debugInfo ? iterator(info.get(), 0) : iterator();
}

inline bool
Units::iterator::atend() const {
    return currentUnit == nullptr;
}

inline
Units::iterator::iterator(const Info *info_, Elf::Off offset)
    : info(info_), currentUnit(info->getUnit(offset)) {}
}

std::ostream &operator << (std::ostream &os, const JSON<Dwarf::Info> &);
std::ostream &operator << (std::ostream &os, const JSON<Dwarf::Macros> &);
std::ostream &operator << (std::ostream &os, const JSON<Dwarf::DIE> &);
}

#endif
