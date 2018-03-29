#ifndef DWARF_H
#define DWARF_H

#include <libpstack/elf.h>
#include <limits>
#include <map>
#include <unordered_map>
#include <list>
#include <vector>
#include <string>

#include <stack>
#include <assert.h>

enum DwarfHasChildren { DW_CHILDREN_yes = 1, DW_CHILDREN_no = 0 };

class DwarfAttribute;
class DwarfEntry;
class DwarfExpressionStack;
class DwarfInfo;
class DwarfLineInfo;
class DWARFReader;
struct DwarfCIE;
struct DwarfFrameInfo;
struct DwarfUnit;

// The DWARF Unit's allEntries map contains the underlying data for the tree.
typedef std::list<DwarfEntry> DwarfEntries;

#define DWARF_TAG(a,b) a = b,
enum DwarfTag {
#include <libpstack/dwarf/tags.h>
    DW_TAG_none = 0x0
};
#undef DWARF_ATE

#define DWARF_ATE(a,b) a = b,
enum DwarfEncoding {
#include <libpstack/dwarf/encodings.h>
    DW_ATE_none = 0x0
};
#undef DWARF_TAG

#define DWARF_FORM(a,b) a = b,
enum DwarfForm {
#include <libpstack/dwarf/forms.h>
    DW_FORM_none = 0x0
};
#undef DWARF_FORM

#define DWARF_ATTR(a,b) a = b,
enum DwarfAttrName {
#include <libpstack/dwarf/attr.h>
    DW_AT_none = 0x0
};
#undef DWARF_ATTR

#define DWARF_LINE_S(a,b) a = b,
enum DwarfLineSOpcode {
#include <libpstack/dwarf/line_s.h>
    DW_LNS_none = -1
};
#undef DWARF_LINE_S

#define DWARF_LINE_E(a,b) a = b,
enum DwarfLineEOpcode {
#include <libpstack/dwarf/line_e.h>
    DW_LNE_none = -1
};
#undef DWARF_LINE_E

struct DwarfAttributeSpec {
    enum DwarfAttrName name;
    enum DwarfForm form;
    DwarfAttributeSpec(DwarfAttrName name_, DwarfForm form_) : name(name_), form(form_) { }
};

struct DwarfAbbreviation {
    intmax_t code;
    DwarfTag tag;
    bool hasChildren;
    std::list<DwarfAttributeSpec> specs;
    DwarfAbbreviation(DWARFReader &, intmax_t);
    DwarfAbbreviation() {}
};

struct DwarfPubname {
    uint32_t offset;
    std::string name;
    DwarfPubname(DWARFReader &r, uint32_t offset);
};

struct DwarfARange {
    uintmax_t start;
    uintmax_t length;
    DwarfARange(uintmax_t start_, uintmax_t length_) : start(start_), length(length_) {}
};

struct DwarfARangeSet {
    uint32_t length;
    uint16_t version;
    uint32_t debugInfoOffset;
    uint8_t addrlen;
    uint8_t segdesclen;
    std::vector<DwarfARange> ranges;
    DwarfARangeSet(DWARFReader &r);
};

struct DwarfPubnameUnit {
    uint16_t length;
    uint16_t version;
    uint32_t infoOffset;
    uint32_t infoLength;
    std::list<DwarfPubname> pubnames;
    DwarfPubnameUnit(DWARFReader &r);
};

struct DwarfBlock {
    off_t offset;
    off_t length;
};

union DwarfValue {
    uintmax_t addr;
    uintmax_t udata;
    intmax_t sdata;
    DwarfBlock block;
    bool flag;
};

std::ostream &operator << (std::ostream &os, const JSON<DwarfInfo> &);

const DwarfEntry *findEntryForFunc(Elf_Addr address, const DwarfEntry *entry);

class DwarfAttribute {
    const DwarfAttributeSpec *spec; /* From abbrev table attached to type */
    DwarfValue value;
public:
    const DwarfEntry *entry;
    DwarfAttribute(DWARFReader &, const DwarfEntry *, const DwarfAttributeSpec *);
    DwarfForm form() const { return spec->form; }
    DwarfAttrName name() const { return spec->name; }
    ~DwarfAttribute() { }
    DwarfAttribute() : spec(0), entry(0) {}
    explicit operator std::string() const;
    explicit operator intmax_t() const;
    explicit operator uintmax_t() const;
    explicit operator bool() const { return value.flag; }
    const DwarfEntry &getReference() const;
    DwarfBlock &block() { return value.block; }
    const DwarfBlock &block() const { return value.block; }
};

class DwarfEntry {
    DwarfEntry() = delete;
    DwarfEntry(const DwarfEntry &) = delete;
public:
    DwarfEntry *parent;
    DwarfEntries children;
    const DwarfUnit *unit;
    const DwarfAbbreviation *type;
    intmax_t offset;
#ifdef NOTYET
    std::unordered_map<DwarfAttrName, DwarfAttribute> attributes;
#else
    std::map<DwarfAttrName, DwarfAttribute> attributes;
#endif
    const DwarfAttribute *attrForName(DwarfAttrName name) const;
    const DwarfEntry *referencedEntry(DwarfAttrName name) const;
    DwarfEntry(DWARFReader &, DwarfTag, DwarfUnit *, intmax_t, DwarfEntry *);
    std::string name() const {
        const DwarfAttribute *attr = attrForName(DW_AT_name);
        if (attr != nullptr)
           return std::string(*attr);
        return "";
    }
};

enum FIType {
    FI_DEBUG_FRAME,
    FI_EH_FRAME
};

class DwarfFileEntry {
    DwarfFileEntry() = delete;
    // copy-constructable.
public:
    std::string name;
    std::string directory;
    unsigned lastMod;
    unsigned length;
    DwarfFileEntry(std::string name_, std::string dir_, unsigned lastMod_, unsigned length_);
    DwarfFileEntry(DWARFReader &r, DwarfLineInfo *info);
};

class DwarfLineState {
    DwarfLineState() = delete;
public:
    uintmax_t addr;
    const DwarfFileEntry *file;
    unsigned line;
    unsigned column;
    unsigned isa;
    bool is_stmt:1;
    bool basic_block:1;
    bool end_sequence:1;
    bool prologue_end:1;
    bool epilogue_begin:1;
    DwarfLineState(DwarfLineInfo *);
};

class DwarfLineInfo {
    DwarfLineInfo(const DwarfLineInfo &) = delete;
public:
    DwarfLineInfo() {}
    bool default_is_stmt;
    uint8_t opcode_base;
    std::vector<int> opcode_lengths;
    std::vector<std::string> directories;
    std::vector<DwarfFileEntry> files;
    std::vector<DwarfLineState> matrix;
    void build(DWARFReader &, const DwarfUnit *);
};

// Override hash for DwarfTag
namespace std {
template <> class hash<DwarfTag> { public: size_t operator() (DwarfTag tag) const {
    return std::hash<int>()(int(tag));
}};
};

struct DwarfUnit {
    DwarfUnit() = delete;
    DwarfUnit(const DwarfUnit &) = delete;
    std::unordered_map<DwarfTag, DwarfAbbreviation> abbreviations;
    std::map<off_t, DwarfEntry *> allEntries;
public:
    const DwarfInfo *dwarf;
    std::shared_ptr<const Reader> io;
    off_t offset;
    size_t dwarfLen;
    void decodeEntries(DWARFReader &r, DwarfEntries &entries, DwarfEntry *parent);
    uint32_t length;
    uint16_t version;
    uint8_t addrlen;
    DwarfEntries entries;
    DwarfLineInfo lines;
    DwarfUnit(const DwarfInfo *, DWARFReader &);
    std::string name() const;
    ~DwarfUnit();
};

struct DwarfFDE {
    uintmax_t iloc;
    uintmax_t irange;
    Elf_Off instructions;
    Elf_Off end;
    Elf_Off cieOff;
    std::vector<unsigned char> augmentation;
    DwarfFDE(DwarfFrameInfo *, DWARFReader &, Elf_Off cieOff_, Elf_Off endOff_);
};

enum DwarfRegisterType {
    UNDEF,
    SAME,
    OFFSET,
    VAL_OFFSET,
    EXPRESSION,
    VAL_EXPRESSION,
    REG,
    ARCH
};

struct DwarfRegisterUnwind {
    enum DwarfRegisterType type;
    union {
        uintmax_t same;
        intmax_t offset;
        uintmax_t reg;
        DwarfBlock expression;
        uintmax_t arch;
    } u;
};

struct DwarfCallFrame {
    std::map<int, DwarfRegisterUnwind> registers;
    int cfaReg;
    DwarfRegisterUnwind cfaValue;
    DwarfCallFrame();
    // default copy constructor is valid.
};

struct DwarfCIE {
    const DwarfFrameInfo *frameInfo;
    uint8_t version;
    uint8_t addressEncoding;
    unsigned char lsdaEncoding;
    bool isSignalHandler;
    unsigned codeAlign;
    int dataAlign;
    int rar;
    Elf_Off instructions;
    Elf_Off end;
    uintmax_t personality;
    std::string augmentation;
    DwarfCIE(const DwarfFrameInfo *, DWARFReader &, Elf_Off);
    DwarfCIE() {}
    DwarfCallFrame execInsns(DWARFReader &r, uintmax_t addr, uintmax_t wantAddr) const;
};

struct DwarfFrameInfo {
    const DwarfInfo *dwarf;
    Elf_Word sectionOffset;
    std::shared_ptr<const Reader> io;
    FIType type;
    std::map<Elf_Addr, DwarfCIE> cies;
    std::list<DwarfFDE> fdeList;
    DwarfFrameInfo(DwarfInfo *, const ElfSection &, FIType);
    DwarfFrameInfo() = delete;
    DwarfFrameInfo(const DwarfFrameInfo &) = delete;
    Elf_Addr decodeCIEFDEHdr(DWARFReader &, FIType, Elf_Off *cieOff); // cieOFF set to -1 if this is CIE, set to offset of associated CIE for an FDE
    const DwarfFDE *findFDE(Elf_Addr) const;
    bool isCIE(Elf_Addr);
    intmax_t decodeAddress(DWARFReader &, int encoding) const;
};

/*
 * A Dwarf Image Cache is an (Elf) Image Cache, but caches DwarfInfo for the
 * ElfObjects also.
 */
class DwarfImageCache : public ImageCache {
    int dwarfHits;
    int dwarfLookups;
    std::map<std::shared_ptr<ElfObject>, std::shared_ptr<DwarfInfo>> dwarfCache;
public:
    std::shared_ptr<DwarfInfo> getDwarf(const std::string &);
    std::shared_ptr<DwarfInfo> getDwarf(std::shared_ptr<ElfObject>);
    DwarfImageCache();
    ~DwarfImageCache();
};

/*
 * DwarfInfo represents the interesting bits of the DWARF data.
 */
class DwarfInfo {
    mutable std::list<DwarfPubnameUnit> pubnameUnits;
    mutable std::list<DwarfARangeSet> aranges;

    // These are mutable so we can lazy-eval them when getters are called, and
    // maintain logical constness.
    mutable std::map<Elf_Off, std::shared_ptr<DwarfUnit>> unitsm;
    mutable std::shared_ptr<DwarfInfo> altDwarf;
    mutable bool altImageLoaded;
    DwarfImageCache &imageCache;
    mutable std::shared_ptr<const Reader> pubnamesh;
    mutable std::shared_ptr<const Reader> arangesh;
public:
    // XXX: info is public because "block" DwarfAttributes need to read from it.
    std::shared_ptr<const Reader> info;
    std::map<Elf_Addr, DwarfCallFrame> callFrameForAddr;
    std::shared_ptr<ElfObject> elf;
    std::unique_ptr<DwarfFrameInfo> debugFrame;
    std::unique_ptr<DwarfFrameInfo> ehFrame;
    std::shared_ptr<const Reader> debugStrings;
    std::shared_ptr<const Reader> abbrev;
    std::shared_ptr<const Reader> lineshdr;
    std::shared_ptr<DwarfInfo> getAltDwarf() const;
    std::list<DwarfARangeSet> &ranges() const;
    const std::list<DwarfPubnameUnit> &pubnames() const;
    std::shared_ptr<DwarfUnit> getUnit(off_t offset);
    std::list<std::shared_ptr<DwarfUnit>> getUnits() const;
    DwarfInfo(std::shared_ptr<ElfObject>, DwarfImageCache &);
    std::vector<std::pair<std::string, int>> sourceFromAddr(uintmax_t addr);

    ~DwarfInfo();
    bool hasRanges() { ranges(); return aranges.size() != 0; }
};

enum DwarfCFAInstruction {
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
    Elf_Off off;
    Elf_Off end;
    uintmax_t getuleb128shift(int *shift, bool &isSigned);
public:
    std::shared_ptr<const Reader> io;
    unsigned addrLen;

    DWARFReader(std::shared_ptr<const Reader> io_, Elf_Off off_ = 0,
          size_t end_ = std::numeric_limits<size_t>::max())
        : off(off_)
        , end(end_ == std::numeric_limits<size_t>::max() ? io_->size() : end_)
        , io(io_)
        , addrLen(ELF_BITS / 8)
    {
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
    Elf_Off getOffset() const { return off; }
    Elf_Off getLimit() const { return end; }
    void setOffset(Elf_Off off_) {
       assert(end >= off_);
       off = off_;
    }
    bool empty() const {
       return off == end;
    }
    Elf_Off getlength(size_t *);
    void skip(Elf_Off amount) { off += amount; }
};

#define DWARF_OP(op, value, args) op = value,
enum DwarfExpressionOp {
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

#endif
