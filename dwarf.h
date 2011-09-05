#ifndef DWARF_H
#define DWARF_H

#include <sys/procfs.h>
#include <sys/ucontext.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>

uint32_t getu32(struct ElfObject *);
uint16_t getu16(struct ElfObject *);
uint8_t getu8(struct ElfObject *);
int8_t gets8(struct ElfObject *);
uintmax_t getuleb128(struct ElfObject *);
intmax_t getsleb128(struct ElfObject *);
const char *getstring(struct ElfObject *);
#define DWARF_MAXREG 128

enum DwarfHasChildren { DW_CHILDREN_yes = 1, DW_CHILDREN_no = 0 };

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

typedef struct tagDwarfAttributeSpec {
    struct tagDwarfAttributeSpec *next;
    enum DwarfAttrName name;
    enum DwarfForm form;
} DwarfAttributeSpec;

typedef struct tagDwarfAbbreviation {
    struct tagDwarfAbbreviation *next;
    intmax_t code;
    intmax_t tag;
    enum DwarfHasChildren hasChildren;
    DwarfAttributeSpec *specs;
} DwarfAbbreviation;

typedef struct tagDwarfPubname {
    struct tagDwarfPubname *next;
    const char *name;
    uint64_t offset;
} DwarfPubname;

typedef struct tagDwarfARange {
    uintmax_t start;
    uintmax_t length;
} DwarfARange;

typedef struct tagDwarfARangeSet {
    struct tagDwarfARangeSet *next;
    uint32_t length;
    uint16_t version;
    uint32_t debugInfoOffset;
    uint8_t addrlen;
    uint8_t segdesclen;
    DwarfARange *ranges;
    int rangeCount;
} DwarfARangeSet;

typedef struct tagDwarfPubnameUnit {
    struct tagDwarfPubnameUnit *next;
    uint16_t length;
    uint16_t version;
    uint32_t infoOffset;
    uint32_t infoLength;
    DwarfPubname *pubnames;
} DwarfPubnameUnit;

typedef struct tagDwarfBlock {
    unsigned char *data;
    uintmax_t length;
} DwarfBlock;

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

typedef struct tagDwarfAttribute {
    struct tagDwarfAttribute *next;
    DwarfAttributeSpec *spec; /* From abbrev table attached to type */
    union DwarfValue value;
} DwarfAttribute;

typedef struct tagDwarfEntry {
    struct tagDwarfEntry *sibling;
    struct tagDwarfEntry *children;
    const DwarfAbbreviation *type;
    DwarfAttribute *attributes;
    intmax_t offset;
} DwarfEntry;

typedef struct tagDwarfUnit {
    struct tagDwarfUnit *next;
    uint32_t length;
    uint16_t version;
    DwarfAbbreviation **abbreviations;
    uint8_t addrlen;
    off_t start;
    off_t end;
    DwarfEntry *entries;
    const struct tagDwarfLineInfo *lines;
} DwarfUnit;

typedef struct tagDwarfFDE {
    struct tagDwarfFDE *next;
    struct tagDwarfCIE *cie;
    uintmax_t iloc;
    uintmax_t irange;
    uint32_t offset;
    off_t instructions;
    off_t end;
    off_t adata;
    uint32_t alen;
} DwarfFDE;

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

typedef struct tagDwarfRegisterUnwind {
    enum DwarfRegisterType type;
    union {
        uintmax_t same;
        uintmax_t offset;
        uintmax_t reg;
        DwarfBlock expression;
        uintmax_t arch;
    } u;
} DwarfRegisterUnwind;

typedef struct tagDwarfCallFrame {
    struct tagDwarfCallFrame *stack;
    DwarfRegisterUnwind registers[MAXREG];
    int cfaReg;
    DwarfRegisterUnwind cfaValue;
} DwarfCallFrame;

typedef struct tagDwarfCIE {
    struct tagDwarfCIE *next;
    DwarfCallFrame defaultFrame;
    uint32_t offset;
    const char *augmentation;
    unsigned codeAlign;
    int dataAlign;
    unsigned long augSize;
    uintmax_t personality;
    unsigned char lsdaEncoding;
    int rar;
    uint8_t version;
    uint8_t addressEncoding;
    off_t instructions;
    off_t end;
} DwarfCIE;

enum FIType {
    FI_DEBUG_FRAME,
    FI_EH_FRAME
};


struct tagDwarfInfo;
typedef struct tagDwarfInfo DwarfInfo;

typedef struct tagFrameInfo {
    enum FIType type;
    DwarfCIE *cieList;
    DwarfFDE *fdeList;
    DwarfInfo *dwarf;
} DwarfFrameInfo;

struct tagDwarfInfo {
    struct ElfObject *elf;
    DwarfUnit *units;
    DwarfPubnameUnit *pubnameUnits;
    DwarfARangeSet *aranges;
    const char *debugStrings;
    off_t lines;
    unsigned addrLen;
    DwarfFrameInfo *debugFrame;
    DwarfFrameInfo *ehFrame;
};

typedef struct tagDwarfFileEntry {
    struct tagDwarfFileEntry *next;
    const char *name;
    const char *directory;
    unsigned lastMod;
    unsigned length;
} DwarfFileEntry;

typedef struct tagDwarfLineState {
    uintmax_t addr;
    DwarfFileEntry *file;
    unsigned line;
    unsigned column;
    unsigned is_stmt:1;
    unsigned basic_block:1;
    unsigned end_sequence:1;
} DwarfLineState;

typedef struct tagDwarfLineInfo {
    const char **directories;
    int default_is_stmt;
    DwarfFileEntry **files;
    DwarfLineState *matrix;
    int rows;
    int maxrows;
} DwarfLineInfo;

void dwarfDump(FILE *out, int, const DwarfInfo *info);
DwarfInfo *dwarfLoad(Process *, struct ElfObject *obj, FILE *errs);
const char *dwarfTagName(enum DwarfTag);
const char *dwarfAttrName(enum DwarfAttrName);
const char *dwarfFormName(enum DwarfForm);
const DwarfAbbreviation *dwarfUnitGetAbbrev(const DwarfUnit *unit, intmax_t code);
uintmax_t getuint(struct ElfObject *, int len);
intmax_t getint(struct ElfObject *, int len);
void dwarfDumpSpec(FILE *out, int indent, const DwarfAttributeSpec *spec);
void dwarfDumpAbbrev(FILE *out, int indent, const DwarfAbbreviation *abbrev);
void dwarfDumpUnit(FILE *, int indent, const DwarfInfo *, const DwarfUnit *);
const char *dwarfSOpcodeName(enum DwarfLineSOpcode code);
const char *dwarfEOpcodeName(enum DwarfLineEOpcode code);
int dwarfSourceFromAddr(DwarfInfo *dwarf, uintmax_t addr, const char **file, int *line);
int dwarfFindFDE(const DwarfFrameInfo *, uintmax_t addr, const DwarfFDE **fde);
void dwarfDumpFDE(FILE *, int, const DwarfInfo *, const DwarfFDE *);

int dwarfComputeCFA(Process *, const DwarfInfo *, DwarfFDE *, DwarfCallFrame *, DwarfRegisters *, uintmax_t addr);
uintmax_t dwarfUnwind(Process *proc, DwarfRegisters *regs, uintmax_t addr);
void dwarfArchGetRegs(const gregset_t *regs, uintmax_t *dwarfRegs);
uintmax_t dwarfGetReg(const DwarfRegisters *regs, int regno);
void dwarfSetReg(DwarfRegisters *regs, int regno, uintmax_t regval);
DwarfRegisters *dwarfPtToDwarf(DwarfRegisters *dwarf, const CoreRegisters *sys);
const DwarfRegisters *dwarfDwarfToPt(CoreRegisters *sys, const DwarfRegisters *dwarf);

/* Linux extensions: */

typedef enum tagDwarfCFAInstruction {

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
} DwarfCFAInstruction;

#define DWARF_OP(op, value, args) op = value,

typedef enum tagDwarfExpressionOp {
#include "dwarf/ops.h"
    LASTOP = 0x100
} DwarfExpressionOp;

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
