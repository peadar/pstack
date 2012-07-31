#ifndef DWARF_H
#define DWARF_H

#include <sys/procfs.h>
#include <sys/ucontext.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <map>

uint32_t getu32(const unsigned char **p);
uint16_t getu16(const unsigned char **p);
uint8_t getu8(const unsigned char **p);
int8_t gets8(const unsigned char **p);
uintmax_t getuleb128(const unsigned char **p);
intmax_t getsleb128(const unsigned char **p);
const char *getstring(const unsigned char **p);
#define DWARF_MAXREG 128

enum DwarfHasChildren { DW_CHILDREN_yes = 1, DW_CHILDREN_no = 0 };
struct DwarfCIE;
struct DwarfInfo;
class DWARFReader;
class DwarfLineInfo;
struct DwarfUnit;
struct DwarfFrameInfo;

typedef struct {
    uintmax_t reg[DWARF_MAXREG];
} DwarfRegisters;

#define DWARF_TAG(a,b) a = b,
enum DwarfTag {
#include "dwarf/tags.h"
    DW_TAG_none = 0x0
};
#undef DWARF_TAG

#define DWARF_FORM(a,b) a = b,
enum DwarfForm {
#include "dwarf/forms.h"
    DW_FORM_none = 0x0
};
#undef DWARF_FORM

#define DWARF_ATTR(a,b) a = b,
enum DwarfAttrName {
#include "dwarf/attr.h"
    DW_AT_none = 0x0
};
#undef DWARF_ATTR

#define DWARF_LINE_S(a,b) a = b,
enum DwarfLineSOpcode {
#include "dwarf/line_s.h"
    DW_LNS_none = -1
};
#undef DWARF_LINE_S

#define DWARF_LINE_E(a,b) a = b,
enum DwarfLineEOpcode {
#include "dwarf/line_e.h"
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
    enum DwarfHasChildren hasChildren;
    std::list<DwarfAttributeSpec *> specs;
    DwarfAbbreviation(DWARFReader &, intmax_t code);
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
    std::list<DwarfPubname *> pubnames;
    DwarfPubnameUnit(DWARFReader &r);
};

struct DwarfBlock {
    off_t offset;
    off_t length;
};

union DwarfValue {
    uintmax_t addr;
    uint8_t data1;
    uint16_t data2;
    uint32_t data4;
    uint64_t data8;
    uintmax_t udata;
    intmax_t sdata;
    const char *string;
    uint16_t ref2;
    uint32_t ref4;
    uint64_t ref8;
    DwarfBlock block;
    char flag;
};

struct DwarfAttribute {
    DwarfAttributeSpec *spec; /* From abbrev table attached to type */
    DwarfValue value;
    DwarfAttribute(DWARFReader &, DwarfUnit *, DwarfAttributeSpec *spec);
};

struct DwarfEntry {
    std::list<DwarfEntry *> children;
    const DwarfAbbreviation *type;
    std::map<DwarfAttrName, DwarfAttribute *> attributes;
    intmax_t offset;
    DwarfAttribute *attrForName(DwarfAttrName name) { return attributes[name]; }
    DwarfEntry(DWARFReader &r, DwarfUnit *unit);
};

struct DwarfUnit {
    DwarfUnit *next;
    uint32_t length;
    uint16_t version;
    std::map<uintmax_t, DwarfAbbreviation *> abbreviations;
    uint8_t addrlen;
    const unsigned char *entryPtr;
    const unsigned char *lineInfo;
    std::list<DwarfEntry *> entries;
    const DwarfLineInfo *lines;
    DwarfUnit(DWARFReader &);
};

struct DwarfFDE {
    DwarfCIE *cie;
    uintmax_t iloc;
    uintmax_t irange;
    Elf_Off instructions;
    Elf_Off end;
    std::vector<unsigned char> aug;
    DwarfFDE(DWARFReader &, DwarfFrameInfo *, Elf_Off, Elf_Off cieid, Elf_Off end);
};

#define MAXREG 128
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
        uintmax_t offset;
        uintmax_t reg;
        DwarfBlock expression;
        uintmax_t arch;
    } u;
};

struct DwarfCallFrame {
    DwarfCallFrame *stack;
    DwarfRegisterUnwind registers[MAXREG];
    int cfaReg;
    DwarfRegisterUnwind cfaValue;
    DwarfCallFrame();
};

struct DwarfCIE {
    uint32_t offset;
    std::string augmentation;
    unsigned codeAlign;
    int dataAlign;
    unsigned long augSize;
    uintmax_t personality;
    unsigned char lsdaEncoding;
    int rar;
    uint8_t version;
    uint8_t addressEncoding;
    Elf_Off instructions;
    Elf_Off end;
    DwarfCIE(DWARFReader &, Elf_Off, Elf_Off);
};

enum FIType {
    FI_DEBUG_FRAME,
    FI_EH_FRAME
};

struct DwarfFrameInfo {
    DwarfInfo *dwarf;
    FIType type;
    std::list<DwarfCIE *> cieList;
    std::list<DwarfFDE *> fdeList;
    DwarfFrameInfo(DWARFReader &, FIType type);
    DwarfCIE *getCIE(Elf_Off offset);
    const DwarfFDE *findFDE(Elf_Addr) const;
};

class DwarfInfo {
public:
    // interesting shdrs from the exe.
    const Elf_Shdr *info, *abbrev, *debstr, *pubnames, *arangesh, *lineshdr, *eh_frame, *debug_frame;
    ElfObject *elf;
    std::list<DwarfUnit *> units;
    std::list<DwarfPubnameUnit *> pubnameUnits;
    std::list<DwarfARangeSet *> aranges;
    char *debugStrings;
    off_t lines;
    unsigned addrLen;
    DwarfFrameInfo *debugFrame;
    DwarfFrameInfo *ehFrame;
    DwarfInfo(ElfObject *object);
    bool sourceFromAddr(uintmax_t addr, std::string &file, int &line);
};

struct DwarfFileEntry {
    std::string name;
    std::string directory;
    unsigned lastMod;
    unsigned length;

    DwarfFileEntry(std::string name_, std::string dir_, unsigned lastMod_, unsigned length_);
    DwarfFileEntry(DWARFReader &r, DwarfLineInfo *info);
};

struct DwarfLineState {
    uintmax_t addr;
    DwarfFileEntry *file;
    unsigned line;
    unsigned column;
    unsigned is_stmt:1;
    unsigned basic_block:1;
    unsigned end_sequence:1;
    DwarfLineState(DwarfLineInfo *);
    void reset(DwarfLineInfo *);
};

struct DwarfLineInfo {
    std::vector<std::string> directories;
    int default_is_stmt;
    std::vector<DwarfFileEntry *> files;
    std::vector<DwarfLineState> matrix;
    DwarfLineInfo(DWARFReader &, const DwarfUnit *);
};

void dwarfDump(FILE *out, int, const DwarfInfo *info);
DwarfInfo *dwarfLoad(Process *, struct ElfObject *obj, FILE *errs);
const char *dwarfTagName(enum DwarfTag);
const char *dwarfAttrName(enum DwarfAttrName);
const char *dwarfFormName(enum DwarfForm);
const DwarfAbbreviation *dwarfUnitGetAbbrev(const DwarfUnit *unit, intmax_t code);
uintmax_t getuint(const unsigned char **p, int len);
intmax_t getint(const unsigned char **p, int len);
void dwarfDumpSpec(FILE *out, int indent, const DwarfAttributeSpec *spec);
void dwarfDumpAbbrev(FILE *out, int indent, const DwarfAbbreviation *abbrev);
void dwarfDumpUnit(FILE *, int indent, const DwarfInfo *, const DwarfUnit *);
const char *dwarfSOpcodeName(enum DwarfLineSOpcode code);
const char *dwarfEOpcodeName(enum DwarfLineEOpcode code);
int dwarfComputeCFA(Process *, const DwarfInfo *, DwarfFDE *, DwarfCallFrame *, DwarfRegisters *, uintmax_t addr);
uintmax_t dwarfUnwind(Process *proc, DwarfRegisters *regs, uintmax_t addr);
void dwarfArchGetRegs(const gregset_t *regs, uintmax_t *dwarfRegs);
uintmax_t dwarfGetReg(const DwarfRegisters *regs, int regno);
void dwarfSetReg(DwarfRegisters *regs, int regno, uintmax_t regval);
DwarfRegisters *dwarfPtToDwarf(DwarfRegisters *dwarf, const CoreRegisters *sys);
const DwarfRegisters *dwarfDwarfToPt(CoreRegisters *sys, const DwarfRegisters *dwarf);

/* Linux extensions: */

enum DwarfCFAInstruction {

    DW_CFA_advance_loc          = 0x40, // XXX: Lower 6 = delta
    DW_CFA_offset               = 0x80, // XXX: lower 6 = reg, (offset:uleb128)
    DW_CFA_restore              = 0xc0, // XXX: lower 6 = register
    DW_CFA_nop                  = 0,
    DW_CFA_set_loc              = 1,    // (address)
    DW_CFA_advance_loc1         = 0x02, // (1-byte delta)
    DW_CFA_advance_loc2         = 0x03, // (2-byte delta)
    DW_CFA_advance_loc4         = 0x04, // (4-byte delta)
    DW_CFA_offset_extended      = 0x05, // ULEB128 register ULEB128 offset  
    DW_CFA_restore_extended     = 0x06, // ULEB128 register   
    DW_CFA_undefined            = 0x07, // ULEB128 register   
    DW_CFA_same_value           = 0x08, // ULEB128 register   
    DW_CFA_register             = 0x09, // ULEB128 register ULEB128 register 
    DW_CFA_remember_state       = 0x0a, //   
    DW_CFA_restore_state        = 0x0b, //   
    DW_CFA_def_cfa              = 0x0c, // ULEB128 register ULEB128 offset  
    DW_CFA_def_cfa_register     = 0x0d, // ULEB128 register   
    DW_CFA_def_cfa_offset       = 0x0e, // ULEB128 offset   
    DW_CFA_def_cfa_expression   = 0x0f, // BLOCK  

    // DWARF 3 only {
    DW_CFA_expression           = 0x10, // ULEB128 register BLOCK 
    DW_CFA_offset_extended_sf   = 0x11, // ULEB128 register SLEB128 offset 
    DW_CFA_def_cfa_sf           = 0x12, // ULEB128 register SLEB128 offset 
    DW_CFA_def_cfa_offset_sf    = 0x13, // SLEB128 offset  
    DW_CFA_val_offset           = 0x14, // ULEB128 ULEB128 
    DW_CFA_val_offset_sf        = 0x15, // ULEB128 SLEB128 
    DW_CFA_val_expression       = 0x16, // ULEB128 BLOCK 
    // }

    DW_CFA_lo_user              = 0x1c,
    DW_CFA_GNU_window_size      = 0x2d, 
    DW_CFA_GNU_args_size        = 0x2e,
    DW_CFA_GNU_negative_offset_extended = 0x2f, 
    DW_CFA_hi_user              = 0x3f,

    /*
     * Value may be this high: ensure compiler generates enough
     * padding to represent this value
     */
    DW_CFA_PAD                  = 0xff
};

#define DWARF_OP(op, value, args) op = value,

enum DwarfExpressionOp {
#include "dwarf/ops.h"
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
