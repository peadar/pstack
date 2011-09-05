#include <unistd.h>
#include <elf.h>
#include <err.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "elfinfo.h"
#include "dwarf.h"

extern int gVerbose;
static int dwarfDecodeAbbrevs(DwarfInfo *, DwarfUnit *);
static void dwarfDumpEntries(FILE *, int , const DwarfInfo *, const DwarfUnit *, const DwarfEntry *);
static void dwarfDumpEntry(FILE *, int, const DwarfInfo *, const DwarfUnit *,  const DwarfEntry *);
static void dwarfDecodeEntries(DwarfInfo *dwarf, DwarfUnit *unit, off_t end, DwarfEntry **entryp);
static void dwarfDumpCFAInsns(FILE *out, int indent, const DwarfInfo *dwarf, off_t e);

uintmax_t
getuint(struct ElfObject *f, int len)
{
    uintmax_t rc = 0;
    int i;
    int roll = 0;
    for (i = 0; i < len; i++) {
        unsigned char c;
        elfRead(f, &c, 1);
        rc += (int)c << roll;
        roll += 8;
    }
    return rc;
}

intmax_t
getint(struct ElfObject *f, int len)
{
    uintmax_t urc = getuint(f, len);
    if (urc & (0x80 << (len - 1))) {
        urc |= (uintmax_t)-1 << len * 8;
    return (intmax_t)urc;
}

uint32_t getu32(struct ElfObject *f) { return getuint(f, 4); }
uint16_t getu16(struct ElfObject *f) { return getuint(f, 2); } 
uint8_t getu8(struct ElfObject *f) { return getuint(f, 1); } }
int8_t gets8(struct ElfObject *f) { return getint(f, 1); }

const char *
getstring(struct ElfObject *obj)
{
    off_t pos = elfGetOffset(obj);
    char c;

    for (;;) {
        elfRead(obj, &c, 1);
        if (c == 0)
            break;
    }
    int len = elfGetOffset(obj) - pos;
    char *p = elfAlloc(obj, len);
    elfSetOffset(obj, pos);
    elfRead(obj, p, len);
    return p;
}

static uintmax_t
getuleb128shift(struct ElfObject *f, int *shift)
{
    uintmax_t result;
    for (result = 0, *shift = 0;;) {
        unsigned char byte;
        elfRead(f, &byte, 1);
        result |= ((uintmax_t)byte & 0x7f) << *shift;
        *shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }
    return result;
}

uintmax_t
getuleb128(struct ElfObject *f)
{
    int shift;
    return getuleb128shift(f, &shift);
}

intmax_t
getsleb128(struct ElfObject *f)
{
    int shift;
    intmax_t result = (intmax_t) getuleb128shift(f, &shift);
    if (result & (1 << (shift - 1)))
        result |= - ((uintmax_t)1 << shift);
    return result;
}

static void
dwarfDumpBlock(FILE *out, int indent, const DwarfBlock *block)
{
    fprintf(out, "%jd bytes\n", block->length);
    hexdump(out, indent, block->data, block->length);
}

static void
dwarfDumpPubname(FILE *out, int indent, const DwarfPubname *name)
{
    fprintf(out, "%s%x: \"%s\"\n", pad(indent), (unsigned)name->offset, name->name);
}

static void
dwarfDumpPubnameUnit(FILE *out, int indent, const DwarfPubnameUnit *punit)
{
    DwarfPubname *name;
    fprintf(out, "%slength: %d\n", pad(indent), punit->length);
    fprintf(out, "%sversion: %d\n", pad(indent), punit->version);
    fprintf(out, "%sinfo offset: %d\n", pad(indent), punit->infoOffset);
    fprintf(out, "%sinfo size: %d\n", pad(indent), punit->infoLength);
    fprintf(out, "%snames:\n", pad(indent));
    for (name = punit->pubnames; name; name = name->next)
        dwarfDumpPubname(out, indent + 4, name);
}

static const DwarfAttribute *
dwarfEntryAttrByName(const DwarfEntry *entry, enum DwarfAttrName what)
{
    DwarfAttribute *attr;
    for (attr = entry->attributes; attr; attr = attr->next)
        if (attr->spec->name == what)
            return attr;
    return 0;
}

static intmax_t
dwarfAttr2Int(const DwarfAttribute *attr)
{
    switch (attr->spec->form) {
    case DW_FORM_data1: return attr->value.data1;
    case DW_FORM_data2: return attr->value.data2;
    case DW_FORM_data4: return attr->value.data4;
    default: abort();
    }
}

static void
dwarfLineStateReset(DwarfLineInfo *li, DwarfLineState *state)
{
    state->addr = 0;
    state->file = li->files[1];
    state->line = 1;
    state->column = 0;
    state->is_stmt = li->default_is_stmt;
    state->basic_block = 0;
    state->end_sequence = 0;
}

static void
dwarfStateAddRow(DwarfLineInfo *li, DwarfLineState *state)
{
    if (li->maxrows == li->rows) {
        li->maxrows += li->maxrows / 2;
        li->matrix = realloc(li->matrix, sizeof *li->matrix * li->maxrows);
    }
    li->matrix[li->rows++] = *state;
}

static DwarfLineInfo *
dwarfDecodeLineInfo(DwarfInfo *dwarf, const DwarfUnit *unit)
{
    DwarfLineState state;
    DwarfLineInfo *pl = elfAlloc(dwarf->elf, sizeof *pl);
    off_t q, end;
    char c;
    uint32_t total_length, prologue_length;
    uint16_t version;

    uint8_t *opcode_lengths;
    int count, opcode_base, min_insn_length, line_range, line_base;
    struct ElfObject *elf = dwarf->elf;
    total_length = getu32(elf);
    end = elfGetOffset(elf) + total_length;
    version = getu16(elf);
    prologue_length = getu32(elf);
    min_insn_length = getu8(elf);
    pl->default_is_stmt = getu8(elf);
    line_base = gets8(elf);
    line_range = getu8(elf);
    opcode_base = getu8(elf);

    opcode_lengths = malloc(opcode_base - 1);
    elfRead(elf, opcode_lengths, opcode_base - 1);

    pl->rows = 0;
    pl->maxrows = 128;
    pl->matrix = malloc(sizeof *pl->matrix * pl->maxrows);

    elfSkip(elf, opcode_base - 1);

    /* count the strings. */
    for (q = elfGetOffset(elf), count = 0;; ++count) {
        elfRead(elf, &c, 1);
        if (c == 0)
            break;
        for (;;) {
            elfRead(elf, &c, 1);
            if (c == 0)
                break;
        }
    }

    pl->directories = elfAlloc(dwarf->elf, sizeof *pl->directories * (count + 1));
    pl->directories[0] = "(compiler CWD)";

    /* seek back to the strings, and read em */
    elfSetOffset(elf, q);
    for (size_t i = 1; i <= count; ++count) {
        const char *p = getstring(dwarf->elf);
        if (p[0] == 0) {
            pl->directories[count] = 0;
            break;
        }
        pl->directories[count] = p;
    }
    elfRead(elf, &c, 1);
    assert(c == 0); // that's the list terminator.

    DwarfFileEntry *list, *cur;
    list = cur = elfAlloc(dwarf->elf, sizeof *list);
    cur->lastMod = 0;
    cur->length = 0;
    cur->name = "(unknown)";
    cur->directory = "(unknown)";

    for (count = 1;; count++) {
        const char *p = getstring(dwarf->elf);
        if (*p == 0)
            break;
        cur = cur->next = elfAlloc(dwarf->elf, sizeof *list);
        cur->name = p;
        cur->directory = pl->directories[getuleb128(elf)];
        cur->lastMod = getuleb128(elf);
        cur->length = getuleb128(elf);
    }
    cur->next = 0;
    pl->files = elfAlloc(dwarf->elf, sizeof *pl->files * (count + 1));
    for (size_t i = 0; cur; cur = cur->next)
        pl->files[i] = cur;

    dwarfLineStateReset(pl, &state);

    while (elfGetOffset(elf) < end) {
        int c = getu8(elf);
        if (c >= opcode_base) {
            /* Special opcode */
            c -= opcode_base;
            int addrIncr = c / line_range;
            int lineIncr = c % line_range + line_base;
            state.addr += addrIncr * min_insn_length;
            state.line += lineIncr;
            dwarfStateAddRow(pl, &state);
            state.basic_block = 0;

        } else if (c == 0) {
            /* Extended opcode */
            int len = getuleb128(elf);
            enum DwarfLineEOpcode code = getu8(elf);
            switch (code) {
            case DW_LNE_end_sequence:
                state.end_sequence = 1;
                dwarfStateAddRow(pl, &state);
                dwarfLineStateReset(pl, &state);
                break;
            case DW_LNE_set_address:
                state.addr = getuint(elf, unit->addrlen);
                break;
            default:
                elfSkip(elf, len - 1);
                abort();
                break;
            }
        } else {
            /* Standard opcode. */
            enum DwarfLineSOpcode std = c;
            int argCount, i;
            switch (std) {
            case DW_LNS_const_add_pc:
                state.addr += ((255 - opcode_base) / line_range) * min_insn_length;
                break;
            case DW_LNS_advance_pc:
                state.addr += getuleb128(elf) * min_insn_length;
                break;
            case DW_LNS_fixed_advance_pc:
                state.addr += getu16(elf) * min_insn_length;
                break;
            case DW_LNS_advance_line:
                state.line += getsleb128(elf);
                break;
            case DW_LNS_set_file:
                state.file = pl->files[getuleb128(elf)];
                break;
            case DW_LNS_copy:
                dwarfStateAddRow(pl, &state);
                state.basic_block = 0;
                break;
            case DW_LNS_set_column:
                state.column = getuleb128(elf);
                break;
            case DW_LNS_negate_stmt:
                state.is_stmt = !state.is_stmt;
                break;
            case DW_LNS_set_basic_block:
                state.basic_block = 1;
                break;
            default:
                argCount = opcode_lengths[std - 1];
                for (i = 0; i < argCount; i++)
                    getuleb128(elf);
                break;
            case DW_LNS_none:
                break;

            }
        }
    }
    return pl;
}


static DwarfEntry *
dwarfDecodeEntry(DwarfInfo *dwarf, DwarfUnit *unit, off_t end)
{
    DwarfAttributeSpec *spec;
    DwarfAttribute *attr, **attrp;
    const DwarfAttribute *cattr;

    DwarfEntry *ent;

    intmax_t offset = elfGetOffset(dwarf->elf) - unit->start;
    intmax_t code = getuleb128(dwarf->elf);
    if (code == 0)
        return 0;
    ent = elfAlloc(dwarf->elf, sizeof *ent);
    ent->type = unit->abbreviations[code];
    ent->offset = offset;

    for (spec = ent->type->specs, attrp = &ent->attributes
            ; spec
            ; spec = spec->next, attrp = &attr->next) {

        attr = *attrp = elfAlloc(dwarf->elf, sizeof *attr);
        attr->spec = spec;
        switch (spec->form) {
        case DW_FORM_addr:
            attr->value.addr = getuint(dwarf->elf, unit->addrlen);
            break;

        case DW_FORM_data1:
            attr->value.data1 = getu8(dwarf->elf);
            break;

        case DW_FORM_data2:
            attr->value.data2 = getu16(dwarf->elf);
            break;

        case DW_FORM_data4:
            attr->value.data4 = getu32(dwarf->elf);
            break;

        case DW_FORM_data8:
            attr->value.data8 = getuint(dwarf->elf, 8);
            break;

        case DW_FORM_sdata:
            attr->value.sdata = getsleb128(dwarf->elf);
            break;

        case DW_FORM_udata:
            attr->value.udata = getuleb128(dwarf->elf);
            break;

        case DW_FORM_strp:
            attr->value.string = dwarf->debugStrings + getu32(dwarf->elf);
            break;

        case DW_FORM_ref2:
            attr->value.ref2 = getu16(dwarf->elf);
            break;

        case DW_FORM_ref4:
            attr->value.ref4 = getu32(dwarf->elf);
            break;

        case DW_FORM_ref8:
            attr->value.ref8 = getuint(dwarf->elf, 8);
            break;

        case DW_FORM_string:
            attr->value.string = getstring(dwarf->elf);
            break;

        case DW_FORM_block1:
            attr->value.block.length = getu8(dwarf->elf);
            attr->value.block.data = elfAlloc(dwarf->elf, attr->value.block.length);
            elfRead(dwarf->elf, attr->value.block.data, attr->value.block.length);
            break;

        case DW_FORM_block2:
            attr->value.block.length = getu16(dwarf->elf);
            attr->value.block.data = elfAlloc(dwarf->elf, attr->value.block.length);
            elfRead(dwarf->elf, attr->value.block.data, attr->value.block.length);
            break;

        case DW_FORM_block4:
            attr->value.block.length = getu32(dwarf->elf);
            attr->value.block.data = elfAlloc(dwarf->elf, attr->value.block.length);
            elfRead(dwarf->elf, attr->value.block.data, attr->value.block.length);
            break;

        case DW_FORM_block:
            attr->value.block.length = getuleb128(dwarf->elf);
            attr->value.block.data = elfAlloc(dwarf->elf, attr->value.block.length);
            elfRead(dwarf->elf, attr->value.block.data, attr->value.block.length);
            break;

        case DW_FORM_flag:
            attr->value.flag = getu8(dwarf->elf);
            break;

        default:
            abort();
            break;
        }
    }

    *attrp = 0;

    switch (ent->type->tag) {
    case DW_TAG_compile_unit:
        cattr = dwarfEntryAttrByName(ent, DW_AT_stmt_list);
        assert(cattr);
        offset = dwarfAttr2Int(cattr);
        elfSetOffset(dwarf->elf, dwarf->lines + offset);
        unit->lines = dwarfDecodeLineInfo(dwarf, unit);
        break;
    }
    if (ent->type->hasChildren)
        dwarfDecodeEntries(dwarf, unit, end, &ent->children);
    else
        ent->children = 0;
    return ent;
}

static void
dwarfDecodeEntries(DwarfInfo *dwarf, DwarfUnit *unit, off_t end, DwarfEntry **entryp)
{
    DwarfEntry *entry;
    for (; elfGetOffset(dwarf->elf) < end; entryp = &entry->sibling) {
        *entryp = entry = dwarfDecodeEntry(dwarf, unit, end);
        if (entry == 0)
            break;
    }
}

static void
dwarfDumpAttributes(FILE *out, int indent, const DwarfAttribute *attr)
{

    for (; attr; attr = attr->next) {
        DwarfAttributeSpec *type = attr->spec;
        const union DwarfValue *value = &attr->value;
        fprintf(out, "%s%s (%s) =", pad(indent), dwarfAttrName(type->name), dwarfFormName(type->form));
        switch (type->form) {
        case DW_FORM_addr:
            fprintf(out, "0x%jx", value->addr);
            break;

        case DW_FORM_data1:
            fprintf(out, "%u (0x%x)", value->data1, value->data1);
            break;

        case DW_FORM_data2:
            fprintf(out, "%u (0x%x)", value->data2, value->data2);
            break;

        case DW_FORM_data4:
            fprintf(out, "%u (0x%x)", value->data4, value->data4);
            break;

        case DW_FORM_data8:
            fprintf(out, "%ju (0x%jx)", value->data8, value->data8);
            break;

        case DW_FORM_sdata:
            fprintf(out, "%jd (0x%jx)", value->sdata, value->sdata);
            break;

        case DW_FORM_udata:
            fprintf(out, "%jd (0x%jx)", value->udata, value->udata);
            break;

        case DW_FORM_string:
        case DW_FORM_strp:
            fprintf(out, "\"%s\"", value->string);
            break;

        case DW_FORM_ref2:
            fprintf(out, "@0x%x", value->ref2);
            break;

        case DW_FORM_ref4:
            fprintf(out, "@0x%jx", (intmax_t)value->ref4);
            break;

        case DW_FORM_ref8:
            fprintf(out, "@0x%jx", value->ref8);
            break;

        case DW_FORM_block1:
        case DW_FORM_block2:
        case DW_FORM_block4:
        case DW_FORM_block:
            dwarfDumpBlock(out, indent + 4, &value->block);
            break;

        case DW_FORM_flag:
            fprintf(out, "%s", value->flag ? "TRUE" : "FALSE");
            break;

        default:
            fprintf(out, "unhandled form %s", dwarfFormName(type->form));
            abort();
            break;
        }
        fprintf(out, "\n");
    }
}

static void
dwarfDumpLineNumbers(FILE *out, int indent, const DwarfUnit *unit)
{
    int i;
    const DwarfLineInfo *pl = unit->lines;
    for (i = 0; i < pl->rows; i++) {
        printf("%s%s (in %s):%d: 0x%jx\n", pad(indent + 4), 
                pl->matrix[i].file->name,
                pl->matrix[i].file->directory,
                pl->matrix[i].line,
                pl->matrix[i].addr);
        if (pl->matrix[i].end_sequence)
            printf("\n");
    }
}

static void
dwarfDumpEntry(FILE *out, int indent, const DwarfInfo *dwarf, const DwarfUnit *unit, const DwarfEntry *entry)
{
    fprintf(stdout, "%sEntry type=%s (off=0x%jx) {\n", pad(indent), dwarfTagName(entry->type->tag), entry->offset);
    switch (entry->type->tag) {
    case DW_TAG_compile_unit:
        // find the line number info
        break;

    }
    dwarfDumpAttributes(out, indent + 4, entry->attributes);
    if (entry->children) {
        fprintf(out, "%schildren: {\n", pad(indent + 4));
        dwarfDumpEntries(out, indent + 8, dwarf, unit, entry->children);
        fprintf(out, "%s}\n", pad(indent + 4));
    }
    fprintf(stdout, "%s}\n", pad(indent));
}

void
dwarfDumpSpec(FILE *out, int indent, const DwarfAttributeSpec *spec)
{
    fprintf(out, "%s%s (%s)\n", pad(indent), dwarfAttrName(spec->name), dwarfFormName(spec->form));
}

void
dwarfDumpAbbrev(FILE *out, int indent, const DwarfAbbreviation *abb)
{
    const DwarfAttributeSpec *spec;
    fprintf(out, "%s%ju: %s %s\n", pad(indent), abb->code, dwarfTagName(abb->tag), abb->hasChildren ? "(has children)" : "");
    for (spec = abb->specs; spec; spec = spec->next)
        dwarfDumpSpec(out, indent + 4, spec);
}

static void
dwarfDumpEntries(FILE *out, int indent, const DwarfInfo *dwarf, const
DwarfUnit *unit, const DwarfEntry *entry)
{
    while (entry) {
        dwarfDumpEntry(out, indent, dwarf, unit, entry);
        entry = entry->sibling;
    }
}

void
dwarfDumpUnit(FILE *out, int indent, const DwarfInfo *dwarf, const DwarfUnit *unit)
{
    fprintf(out, "%slength: %u\n", pad(indent), unit->length);
    fprintf(out, "%sversion: %u\n", pad(indent), unit->version);
    fprintf(out, "%saddrlen: %u\n", pad(indent), unit->addrlen);
    dwarfDumpLineNumbers(out, indent, unit);
    dwarfDumpEntries(out, indent, dwarf, unit, unit->entries);
}

static void
dwarfDumpARangeSet(FILE *out, int indent, const DwarfARangeSet *ranges)
{
    int i;
    fprintf(out, "%slength: %d\n", pad(indent), (int)ranges->length);
    fprintf(out, "%sversion: %d\n", pad(indent), (int)ranges->version);
    fprintf(out, "%saddrlen: %d\n", pad(indent), (int)ranges->addrlen);
    fprintf(out, "%sdescrlen: %d\n", pad(indent), (int)ranges->segdesclen);
    fprintf(out, "%srangecount: %d\n", pad(indent), (int)ranges->rangeCount);
    for (i = 0; i < ranges->rangeCount; i++)
        fprintf(out, "%s0x%jx + 0x%jx = 0x%jx\n", pad(indent),
            ranges->ranges[i].start, ranges->ranges[i].length,
            ranges->ranges[i].start + ranges->ranges[i].length);

}

static void
dwarfDumpCIE(FILE *out, int indent, const DwarfInfo *dwarf, const DwarfCIE *cie)
{
    fprintf(out, "%sCIE {\n", pad(indent));
    fprintf(out, "%sversion: %d\n", pad(indent + 4), cie->version);
    fprintf(out, "%saugmentation: \"%s\"\n", pad(indent + 4), cie->augmentation);
    fprintf(out, "%scodeAlign: %u\n", pad(indent + 4), cie->codeAlign);
    fprintf(out, "%sdataAlign: %d\n", pad(indent + 4), cie->dataAlign);
    fprintf(out, "%sreturn address reg: %d\n", pad(indent + 4), cie->rar);
    fprintf(out, "%soffset: 0x%x\n", pad(indent + 4), cie->offset);
    fprintf(out, "%saug size: 0x%lx\n", pad(indent + 4), cie->augSize);
    elfSetOffset(dwarf->elf, cie->instructions);
    dwarfDumpCFAInsns(out, indent + 4, dwarf, cie->end);
    fprintf(out, "%s}\n", pad(indent));
}

void
dwarfDumpFDE(FILE *out, int indent, const DwarfInfo *dwarf, const DwarfFDE *fde)
{
    fprintf(out, "%sFDE {\n", pad(indent));
    fprintf(out, "%scie: %x\n", pad(indent + 4), fde->cie->offset);
    fprintf(out, "%sloc: 0x%jx\n", pad(indent + 4), fde->iloc);
    fprintf(out, "%srange: 0x%jx\n", pad(indent + 4), fde->irange);
    fprintf(out, "%soffset: 0x%x\n", pad(indent + 4), fde->offset);
    fprintf(out, "%sauglen: 0x%x\n", pad(indent + 4), fde->alen);
    elfSetOffset(dwarf->elf, fde->instructions);
    dwarfDumpCFAInsns(out, indent + 4, dwarf, fde->end);
    fprintf(out, "%s}\n", pad(indent));
}

void
dwarfDumpFrameInfo(FILE *out, const DwarfFrameInfo *info, int indent)
{
    const DwarfFDE *fde;
    const DwarfCIE *cie;

    for (cie = info->cieList; cie; cie = cie->next)
        dwarfDumpCIE(out, indent, info->dwarf, cie);
    for (fde = info->fdeList; fde; fde = fde->next)
        dwarfDumpFDE(out, indent, info->dwarf, fde);
}

void
dwarfDump(FILE *out, int indent, const DwarfInfo *dwarf)
{
    const DwarfUnit *unit;
    const DwarfPubnameUnit *pubunit;
    const DwarfARangeSet *arange;
    int i;

    for (unit = dwarf->units, i = 0; unit; unit = unit->next, i++) {
        fprintf(out, "%sTranslationUnit %d {\n", pad(indent), i);
        dwarfDumpUnit(out, indent + 4, dwarf, unit);
        fprintf(out, "%s}\n", pad(indent));
    }

    for (pubunit = dwarf->pubnameUnits, i = 0; pubunit; i++, pubunit = pubunit->next) {
        fprintf(out, "%spubname unit %d{\n", pad(indent), i);
        dwarfDumpPubnameUnit(out, indent + 4, pubunit);
        fprintf(out, "%s}\n", pad(indent));
    }

    for (arange = dwarf->aranges, i = 0; arange; i++, arange = arange->next) {
        fprintf(out, "%sarange set %d {\n", pad(indent), i);
        dwarfDumpARangeSet(out, indent + 4, arange);
        fprintf(out, "%s}\n", pad(indent));
    }

    if (dwarf->debugFrame) {
        fprintf(out, "%sDebug Frame Information {\n", pad(indent));
        dwarfDumpFrameInfo(out, dwarf->debugFrame, indent + 4);
        fprintf(out, "%s}\n", pad(indent));
    }

    if (dwarf->ehFrame) {
        fprintf(out, "%sEH Frame Information {\n", pad(indent));
        dwarfDumpFrameInfo(out, dwarf->ehFrame, indent + 4);
        fprintf(out, "%s}\n", pad(indent));
    }

}

static int
dwarfDecodeAbbrevs(DwarfInfo *dwarf, DwarfUnit *unit)
{
    DwarfAbbreviation *first, *abb, **abbp;
    uintmax_t code;
    DwarfAttributeSpec *spec, **specp;
    static uintmax_t abbrCount = 0;
    struct ElfObject *elf = dwarf->elf;

    for (abbp = &first; (code = getuleb128(elf)) != 0; abbp = &abb->next) {
        abb = *abbp = elfAlloc(dwarf->elf, sizeof *abb);
        abb->code = code;
        if (code >= abbrCount)
            abbrCount = code + 1;

        abb->tag = getuleb128(elf);
        abb->hasChildren = getu8(elf);
        specp = &abb->specs;
        for (;;) {
            uintmax_t name, form;
            name = getuleb128(elf);
            form = getuleb128(elf);
            if (name == 0 && form == 0)
                break;
            *specp = spec = elfAlloc(elf, sizeof *spec);
            specp = &spec->next;
            spec->name = name;
            spec->form = form;
        }
        *specp = 0;
    }
    unit->abbreviations = elfAlloc(dwarf->elf, sizeof *unit->abbreviations * abbrCount);
    for (abb = first; abb; abb = abb->next)
        unit->abbreviations[abb->code] = abb;

    *abbp = 0;
    return 1;
}

static void
dwarfDumpCFAInsns(FILE *out, int indent, const DwarfInfo *dwarf, off_t e)
{
    uint16_t u16;
    uint32_t u32;
    uintmax_t reg, reg2, offset;
    uintmax_t loc = 0;
    struct ElfObject *elf = dwarf->elf;

    fprintf(out, "%sCFA instructions {\n", pad(indent));
    indent += 4;
    while (elfGetOffset(elf) < e) {
        uint8_t op = getu8(elf), u8;
        switch (op >> 6) {
        case 1:
            loc += op & 0x3f;
            fprintf(out, "%sDW_CFA_advance_loc(delta=0x%x cur=0x%jx)\n",
                    pad(indent), op & 0x3f, loc);
            break;
        case 2:
            offset = getuleb128(elf);
            fprintf(out, "%sDW_CFA_offset(register=0x%x, offset=0x%jx)\n",
                    pad(indent), op & 0x3f, offset);
            break;
        case 3:
            fprintf(out, "%sDW_CFA_restore(register=0x%x)\n",
                    pad(indent), op & 0x3f);
            break;

        case 0:
            switch (op & 0x3f) {
            case 0x0:
                fprintf(out, "%sDW_CFA_nop\n", pad(indent));
                break;
            case 0x1:
                offset = loc = getuint(elf, dwarf->addrLen);
                fprintf(out, "%sDW_CFA_set_loc(0x%jx, cur=%jx)\n", pad(indent), offset, loc);
                break;
            case 0x2:
                u8 = getu8(elf);
                loc += u8;
                fprintf(out, "%sDW_CFA_advance_loc1(delta=0x%x, cur=0x%jx)\n",
                        pad(indent), u8, loc);
                break;
            case 0x3:
                u16 = getu16(elf);
                loc += u16;
                fprintf(out, "%sDW_CFA_advance_loc2(delta=0x%x, loc=0x%jx)\n",
                        pad(indent), u16, loc);
                break;
            case 0x4:
                u32 = getu32(elf);
                loc += u32;
                fprintf(out, "%sDW_CFA_advance_loc4(delta=0x%x, loc=0x%jx)\n",
                        pad(indent), u32, loc);
                break;
            case 0x5:
                reg = getuleb128(elf);
                offset = getuleb128(elf);
                fprintf(out, "%sDW_CFA_offset_extended(reg=0x%jx, offset=0x%jx)\n",
                        pad(indent), reg, offset);
                break;
            case 0x6:
                reg = getuleb128(elf);
                fprintf(out, "%sDW_CFA_restore_extended(reg=0x%jx)\n",
                        pad(indent), reg);
                break;
            case 0x7:
                reg = getuleb128(elf);
                fprintf(out, "%sDW_CFA_undefined(reg=0x%jx)\n", pad(indent), reg);
                break;
            case 0x8:
                reg = getuleb128(elf);
                fprintf(out, "%sDW_CFA_same_value(reg=0x%jx)\n",
                        pad(indent), reg);
                break;
            case 0x9:
                reg = getuleb128(elf);
                reg2 = getuleb128(elf);
                fprintf(out, "%sDW_CFA_register(reg1=0x%jx, reg2=0x%jx)\n",
                        pad(indent), reg, reg2);
                break;
            case 0xa:
                fprintf(out, "%sDW_CFA_remember_state()\n", pad(indent));
                break;
            case 0xb:
                fprintf(out, "%sDW_CFA_restore_state()\n", pad(indent));
                break;
            case 0xc: 
                reg = getuleb128(elf);
                offset = getuleb128(elf);
                fprintf(out, "%sDW_CFA_def_cfa(reg=0x%jx, offset=0x%jx)\n",
                        pad(indent), reg, offset);
                break;
            case 0xd:
                reg = getuleb128(elf);
                fprintf(out, "%sDW_CFA_def_cfa_register(reg=0x%jx)\n",
                        pad(indent), reg);
                break;
            case 0xe:
                offset = getuleb128(elf);
                fprintf(out, "%sDW_CFA_def_cfa_offset(offset=0x%jx)\n",
                        pad(indent), offset);
                break;

            case 0xf:
                offset = getuleb128(elf);
                fprintf(out, "%sDW_CFA_def_cfa_expression(size=0x%jx)\n",
                        pad(indent), offset);
                elfSkip(elf, offset);
                break;

            case 0x10:
                reg = getuleb128(elf);
                offset = getuleb128(elf);
                fprintf(out, "%sDW_CFA_expression(reg=0x%jx, size=0x%jx)\n",
                        pad(indent), reg, offset);
                elfSkip(elf, offset);
                break;

            case 0x2e: // DW_CFA_GNU_args_size
                offset = getuleb128(elf);
                fprintf(out, "%sFW_CFA_GNU_args_size(xxx=0x%jx)\n", pad(indent), offset);
                break;

            case 0x2d: // DW_CFA_GNU_window_size
            case 0x2f: // DW_CFA_GNU_negative_offset_extended
            default:
                fprintf(out, "%sDW_CFA_foobar(0x%x)\n", pad(indent), op);
                goto done;
                break;
            }
            break;
        }
    }
done:
    indent -= 4;
    fprintf(out, "%s}\n", pad(indent));
}

static void
frameDefault(DwarfCallFrame *frame)
{
    int i;
    for (i = 0; i < MAXREG; i++)
        frame->registers[i].type = UNDEF;
    frame->cfaReg = 0;
    frame->cfaValue.type = UNDEF;
}


#define STACK_MAX 1024
typedef struct tagDwarfExpressionStack {
    intmax_t content[STACK_MAX];
    size_t sp;
} DwarfExpressionStack;

void
dwarfStackInit(DwarfExpressionStack *stack)
{
    stack->sp = 0;
}

void
dwarfStackPush(DwarfExpressionStack *stack, intmax_t value)
{
    stack->content[stack->sp++] = value;
}

intmax_t
dwarfStackPop(DwarfExpressionStack *stack)
{
    return stack->content[--stack->sp];
}


static const char *
opname(DwarfExpressionOp op)
{
#define DWARF_OP(name, value, args) case name: return #name;
    switch (op) {
#include "dwarf/ops.h"
        default: return "(unknown operation)";
    }
#undef DWARF_OP
}

static intmax_t
dwarfEvalExpr(
            Process *proc,
            DwarfInfo *dwarf,
            const DwarfRegisters *frame,
            DwarfExpressionStack *stack,
            off_t p, off_t e)
{
    if (gVerbose)
        fprintf(stderr, "dwarfEvalExpr:\n");
    for (elfSetOffset(dwarf->elf, p);  elfGetOffset(dwarf->elf) < e;) {
        DwarfExpressionOp op = (DwarfExpressionOp) getu8(dwarf->elf);
        if (gVerbose)
            fprintf(stderr, "\t%s\n", opname(op));
        switch (op) {
            case DW_OP_deref: {
                intmax_t addr = dwarfStackPop(stack);
                void *value; //XXX: TODO addrlen
                procReadMem(proc, &value, (Elf_Addr)addr, sizeof value);
                dwarfStackPush(stack, (intmax_t)(intptr_t)value);
                break;
            }

            case DW_OP_breg0: case DW_OP_breg1: case DW_OP_breg2: case DW_OP_breg3:
            case DW_OP_breg4: case DW_OP_breg5: case DW_OP_breg6: case DW_OP_breg7:
            case DW_OP_breg8: case DW_OP_breg9: case DW_OP_breg10: case DW_OP_breg11:
            case DW_OP_breg12: case DW_OP_breg13: case DW_OP_breg14: case DW_OP_breg15:
            case DW_OP_breg16: case DW_OP_breg17: case DW_OP_breg18: case DW_OP_breg19:
            case DW_OP_breg20: case DW_OP_breg21: case DW_OP_breg22: case DW_OP_breg23:
            case DW_OP_breg24: case DW_OP_breg25: case DW_OP_breg26: case DW_OP_breg27:
            case DW_OP_breg28: case DW_OP_breg29: case DW_OP_breg30: case DW_OP_breg31: {
                intmax_t offset = getsleb128(dwarf->elf);
                dwarfStackPush(stack, frame->reg[op - DW_OP_breg0] + offset);
                break;
            }

            default: 
                fprintf(stderr, "unknown op %d (0x%x)\n", op, op);
                abort();

            // TODO
        }
    }
    return dwarfStackPop(stack);
}

static uintmax_t
dwarfExecInsns(Process *proc, const DwarfInfo *dwarf, DwarfCIE *cie, DwarfCallFrame *frame,
        off_t p, off_t e, uintmax_t addr, uintmax_t wantAddr)
{
    DwarfCallFrame *tmpFrame;
    DwarfCallFrame *startFrame = frame;
    uintmax_t offset;
    int reg, reg2;

    while (p < e && addr <= wantAddr) {
        uint8_t rawOp = getu8(dwarf->elf);
        reg = rawOp &0x3f;
        DwarfCFAInstruction op = (DwarfCFAInstruction)(rawOp & ~0x3f);
        switch (op) {
        case DW_CFA_advance_loc:
            addr += reg * cie->codeAlign;
            break;

        case DW_CFA_offset:
            offset = getuleb128(dwarf->elf);
            frame->registers[reg].type = OFFSET;
            frame->registers[reg].u.offset = offset * cie->dataAlign;
            break;

        case DW_CFA_restore:
            frame->registers[reg] = cie->defaultFrame.registers[reg];
            break;

        case 0:
            op = (DwarfCFAInstruction)(rawOp & 0x3f);
            switch (op) {
            case DW_CFA_nop:
                break;
                
            case DW_CFA_set_loc:
                addr = getuint(dwarf->elf, dwarf->addrLen);
                break;

            case DW_CFA_advance_loc1:
                addr += getu8(dwarf->elf) * cie->codeAlign;
                break;

            case DW_CFA_advance_loc2:
                addr += getu16(dwarf->elf) * cie->codeAlign;
                break;

            case DW_CFA_advance_loc4:
                addr += getu32(dwarf->elf) * cie->codeAlign;
                break;

            case DW_CFA_offset_extended:
                reg = getuleb128(dwarf->elf);
                offset = getuleb128(dwarf->elf);
                frame->registers[reg].type = OFFSET;
                frame->registers[reg].u.offset = offset * cie->dataAlign;
                break;

            case DW_CFA_restore_extended:
                reg = getuleb128(dwarf->elf);
                frame->registers[reg] = cie->defaultFrame.registers[reg];
                break;

            case DW_CFA_undefined:
                reg = getuleb128(dwarf->elf);
                frame->registers[reg].type = UNDEF;
                break;

            case DW_CFA_same_value:
                reg = getuleb128(dwarf->elf);
                frame->registers[reg].type = SAME;
                break;

            case DW_CFA_register:
                reg = getuleb128(dwarf->elf);
                reg2 = getuleb128(dwarf->elf);
                frame->registers[reg].type = REG;
                frame->registers[reg].u.reg = reg2;
                break;

            case DW_CFA_remember_state:
                tmpFrame = malloc(sizeof *frame);
                *tmpFrame = *frame;
                tmpFrame->stack = frame;
                frame = tmpFrame;
                break;

            case DW_CFA_restore_state:
                tmpFrame = frame;
                frame = frame->stack;
                free(tmpFrame);
                break;

            case DW_CFA_def_cfa:
                frame->cfaReg = getuleb128(dwarf->elf);
                frame->cfaValue.type = OFFSET;
                frame->cfaValue.u.offset = getuleb128(dwarf->elf);
                break;

            case DW_CFA_def_cfa_sf:
                frame->cfaReg = getuleb128(dwarf->elf);
                frame->cfaValue.type = OFFSET;
                frame->cfaValue.u.offset = getsleb128(dwarf->elf) * cie->dataAlign;
                break;

            case DW_CFA_def_cfa_register:
                frame->cfaReg = getuleb128(dwarf->elf);
                frame->cfaValue.type = OFFSET;
                break;

            case DW_CFA_def_cfa_offset:
                frame->cfaValue.type = OFFSET;
                frame->cfaValue.u.offset = getuleb128(dwarf->elf);
                break;

            case DW_CFA_def_cfa_offset_sf:
                frame->cfaValue.type = OFFSET;
                frame->cfaValue.u.offset = getuleb128(dwarf->elf) * cie->dataAlign;
                break;

            case DW_CFA_val_expression: {
                DwarfRegisterUnwind *unwind;
                reg = getuleb128(dwarf->elf);
                offset = getuleb128(dwarf->elf);
                unwind = &frame->registers[reg];
                unwind->type = VAL_EXPRESSION;
                unwind->u.expression.data = elfAlloc(dwarf->elf, offset);
                unwind->u.expression.length = offset;
                elfRead(dwarf->elf, unwind->u.expression.data, unwind->u.expression.length);
                break;
            }

            case DW_CFA_expression: {
                DwarfRegisterUnwind *unwind;
                reg = getuleb128(dwarf->elf);
                offset = getuleb128(dwarf->elf);
                unwind = &frame->registers[reg];
                unwind->type = EXPRESSION;
                unwind->u.expression.length = offset;
                unwind->u.expression.data = elfAlloc(dwarf->elf, offset);
                elfRead(dwarf->elf, unwind->u.expression.data, unwind->u.expression.length);
                break;
            }

            case DW_CFA_def_cfa_expression: {
                frame->cfaValue.type = EXPRESSION;
                offset = getuleb128(dwarf->elf);
                frame->cfaValue.u.expression.data = elfAlloc(dwarf->elf, offset);
                frame->cfaValue.u.expression.length = offset;
                elfRead(dwarf->elf,
                    frame->cfaValue.u.expression.data,
                    frame->cfaValue.u.expression.length);
                break;
            }

            // Can't deal with anything else yet.
            case DW_CFA_GNU_window_size:
            case DW_CFA_GNU_negative_offset_extended:
            default:
                abort();
                goto done;
            }
            break;

        default:
            abort();
            goto done;
            break;
        }
    }

done:
    // If the frame we stopped at was "pushed", copy it to the requested
    // frame, and free the entire stack.
    if (startFrame != frame) {
        *startFrame = *frame;
        while (frame != startFrame) {
            tmpFrame = frame;
            frame = frame->stack;
            free(tmpFrame);
        }
    }
    return addr;
}


static DwarfCIE *
dwarfGetCIE(DwarfFrameInfo *info, uint32_t offset)
{
    DwarfCIE *cie;
    for (cie = info->cieList; cie; cie = cie->next) {
        if (cie->offset == offset)
            return cie;
    }
    fprintf(stderr, "no cie at 0x%x\n", offset);
    abort();
    return 0;

}

intmax_t
decodeAddress(DwarfFrameInfo *info, int encoding)
{
    intmax_t base;
    struct ElfObject *elf = info->dwarf->elf;

    off_t off = elfGetOffset(elf);
    switch (encoding & 0xf) {
    case DW_EH_PE_sdata2:
        base = getint(elf, 2);
        break;
    case DW_EH_PE_sdata4:
        base = getint(elf, 4);
        break;
    case DW_EH_PE_sdata8:
        base = getint(elf, 8);
        break;
    case DW_EH_PE_udata2:
        base = getuint(elf, 2);
        break;
    case DW_EH_PE_udata4:
        base = getuint(elf, 4);
        break;
    case DW_EH_PE_udata8:
        base = getuint(elf, 8);
        break;
    case DW_EH_PE_sleb128:
        base = getsleb128(elf);
        break;
    case DW_EH_PE_uleb128:
        base = getuleb128(elf);
        break;
    case DW_EH_PE_absptr:
    default:
        abort();
        break;
    }

    switch (encoding & 0xf0) {
    case 0:
        break;
    case DW_EH_PE_pcrel:
        base += off + info->dwarf->elf->base;
        break;
    }
    return base;
}

static DwarfFDE *
decodeFDE(DwarfFrameInfo *info, uint32_t offset, uint32_t cieid, off_t off, off_t end)
{
    DwarfFDE *fde = elfAlloc(info->dwarf->elf, sizeof *fde);
    struct ElfObject *elf = info->dwarf->elf;

    uint32_t cieOff = info->type == FI_EH_FRAME ? offset - cieid - 4 : cieid;
    fde->cie = dwarfGetCIE(info, cieOff);
    fde->offset = elfGetOffset(elf);
    fde->end = end;
    fde->iloc = decodeAddress(info, fde->cie->addressEncoding);
    fde->irange = decodeAddress(info, fde->cie->addressEncoding & 0xf);
    if (fde->cie->augmentation && fde->cie->augmentation[0] == 'z') {
        fde->alen = getuleb128(elf);
        fde->adata = elfGetOffset(elf);
        elfSkip(elf, fde->alen);
    } else {
        fde->alen = 0;
        fde->adata = 0;
    }
    fde->instructions = elfGetOffset(elf);
    return fde;
}


#define T(a) case a: return #a;
static const char *
DW_EH_PE_typeStr(unsigned char c)
{
    switch (c & 0xf) {
        T(DW_EH_PE_absptr)
        T(DW_EH_PE_uleb128)
        T(DW_EH_PE_udata2)
        T(DW_EH_PE_udata4)
        T(DW_EH_PE_udata8)
        T(DW_EH_PE_sleb128)
        T(DW_EH_PE_sdata2)
        T(DW_EH_PE_sdata4)
        T(DW_EH_PE_sdata8)
        default: return "(unknown)";
    }
}

static const char *
DW_EH_PE_relStr(unsigned char c)
{
    switch (c & 0xf0) {
    T(DW_EH_PE_pcrel)
    T(DW_EH_PE_textrel)
    T(DW_EH_PE_datarel)
    T(DW_EH_PE_funcrel)
    T(DW_EH_PE_aligned)
    default: return "(unknown)";
    }

}
#undef T

static DwarfCIE *
decodeCIE(Process *proc, DwarfFrameInfo *info, off_t end)
{
    struct ElfObject *elf = info->dwarf->elf;
    DwarfCIE *cie = elfAlloc(elf, sizeof *cie);
    cie->offset = elfGetOffset(elf);
    cie->next = info->cieList;
    info->cieList = cie;

    cie->version = getu8(elf);
    cie->augmentation = getstring(elf);
    cie->codeAlign = getuleb128(elf);
    cie->dataAlign = getsleb128(elf);
    cie->rar = getu8(elf);

    // Get augmentations...

    cie->augSize = 0;
#if 1 || ELF_BITS == 32
    cie->addressEncoding = DW_EH_PE_udata4;
#elif ELF_BITS == 64
    cie->addressEncoding = DW_EH_PE_udata8;
#else
    #error "no default address encoding"
#endif

    const char *augStr = cie->augmentation;
    if (augStr && augStr[0]) {
        if (*augStr == 'z') {
            augStr++;
            cie->augSize = getuleb128(elf);
            off_t endaug = elfGetOffset(elf) + cie->augSize;

            for (off_t const char *augEnd = augStr + cie->augSize; augStr < augEnd; ++augStr) {
                switch (*augStr) {
                    case 'P': {
                        unsigned char encoding = getu8(elf);
                        cie->personality = decodeAddress(info, encoding, 0);
                        break;
                    }
                    case 'L':
                        cie->lsdaEncoding = getu8(elf);
                        break;
                    case 'R':
                        cie->addressEncoding = getu8(elf);
                        if (gVerbose)
                            fprintf(stderr, "CIE address encoding: %s|%s\n",
                                DW_EH_PE_typeStr(cie->addressEncoding),
                                DW_EH_PE_relStr(cie->addressEncoding));
                        break;
                    default:
                        fprintf(stderr, "unknown augmentation '%c'\n", *augStr);
                        // The augmentations are in order, so we can't make any sense of the remaining data in the
                        // augmentation block
                        augStr = augEnd;
                        break;
                }
            }
            elfSetOffset(elf, endaug);
        } else {
            fprintf(stderr, "augmentation without length delimiter: '%s'\n", augStr);
        }
    }

    cie->instructions = elfGetOffset(elf);
    cie->end = end;
    // Get the starting point for this CIE.
    frameDefault(&cie->defaultFrame);
    dwarfExecInsns(proc, info->dwarf, cie, &cie->defaultFrame, cie->instructions, end, 0, 0);
    return cie;
}

static const unsigned char *
decodeCIEFDEHdr(struct ElfObject *obj, uint32_t *id, enum FIType type)
{
    const unsigned char *next;
    unsigned length = getu32(obj);
    if (length >= 0xfffffff0) {
        switch (length) {
            case 0xffffffff:
                fprintf(stderr, "extended lengh field\n");
                length = getuint(p, 8);
                break;
            default:
                return 0;
        }
    }
    if (length == 0)
        return 0;

    next = *p + length;
    // XXX: Dwarf 2 = 4 bytes, Dwarf 3 = word size.
    *id = getuint(p, 4); //ELF_BITS/8);
    return next;
}

static DwarfFrameInfo *
dwarfDecodeFrameInfo(Process *proc, DwarfInfo *dwarf, off_t len, enum FIType type)
{
    DwarfFDE *fde, **fdep;
    uint32_t cieid;
    DwarfFrameInfo *info = elfAlloc(dwarf->elf, sizeof *info);

    info->dwarf = dwarf;
    info->type = type;
    info->fdeList = 0;
    info->cieList = 0;

    // decode in 2 passes: first for CIE, then for FDE
    const unsigned char *next;
    off_t start = elfGetOffset(dwarf->elf);

    while ((offset = elfGetOffset(dwarf->elf)) != len) {
        if (decodeCIEFDEHdr(elf, &cieid, type) == 0)
            break;
        if ((type == FI_DEBUG_FRAME && cieid == 0xffffffff) || (type == FI_EH_FRAME && cieid == 0))
            decodeCIE(proc, info, next);
    }

    fdep = &info->fdeList;
    for (const unsigned char *p = start; p < e; p = next) {
        if (decodeCIEFDEHdr(elf, &p, &cieid, type) == 0)
            break;
        if ((type == FI_DEBUG_FRAME && cieid != 0xffffffff) || (type == FI_EH_FRAME && cieid != 0)) {
            *fdep = fde = decodeFDE(info, p - start, cieid, &p, next);
            fdep = &fde->next;
        }
    }
    *fdep = 0;
    return info;
}

DwarfInfo *
dwarfLoad(Process *proc, struct ElfObject *obj, FILE *errs)
{
    int rc;
    DwarfARangeSet *arange, **arangep;
    DwarfPubname *pubname, **pubnamep;
    DwarfPubnameUnit *pubunit, **pubunitp;
    const unsigned char *start, *p, *e, *next;
    DwarfInfo *dwarf;
    DwarfUnit *unit, **unitp;
    const Elf_Shdr *info, *abbrev, *debstr, *pubnames, *aranges, *lines, *eh_frame, *debug_frame;

    struct {
        const char *name;
        const Elf_Shdr **header;
    } *loadsectsp, loadsects[] = {
        {".eh_frame", &eh_frame },
        {".debug_info", &info },
        {".debug_abbrev", &abbrev },
        {".debug_str", &debstr },
        {".debug_line", &lines },
        {".debug_frame", &debug_frame },
        {".debug_pubnames", &pubnames}, 
        {".debug_aranges", &aranges}, 
        { 0, 0 }
    };

    dwarf = elfAlloc(obj, sizeof *dwarf);
    memset(dwarf, 0, sizeof *dwarf);
    dwarf->elf = obj;
    dwarf->addrLen = 
#ifdef __i386__
        4
#endif
#ifdef __amd64__
        8
#endif
    ;

    // Load all sections we're interested in.
    for (loadsectsp = loadsects; loadsectsp->name; loadsectsp++) {
        rc = elfFindSectionByName(obj, loadsectsp->name, loadsectsp->header);
        if (rc == SHN_UNDEF)
            *loadsectsp->header = 0;
    }

    if (eh_frame) {
        elfSetOffset(obj, eh_frame->sh_offset);
        dwarf->ehFrame = dwarfDecodeFrameInfo(proc, dwarf, eh_frame->sh_size, FI_EH_FRAME);
    } else {
        dwarf->ehFrame = 0;
    }

    if (debug_frame) {
        elfSetOffset(obj, debug_frame->sh_offset);
        dwarf->debugFrame = dwarfDecodeFrameInfo(proc, dwarf, debug_frame->sh_size, FI_DEBUG_FRAME);
    } else {
        dwarf->debugFrame = 0;
    }

    dwarf->debugStrings = debstr
            ? (const char *)(obj->fileData + debstr->sh_offset)
            : 0;
    dwarf->lines = lines ? lines->sh_offset : 0;

    unitp = &dwarf->units;
    if (info) {
        for (p = info->sh_offset + obj->fileData, e = p + info->sh_size; p < e; p = next) {
            /* New translation unit in this debug info */
            *unitp = unit = elfAlloc(obj, sizeof *unit);
            memset(unit, 0, sizeof *unit);
            unitp = &unit->next;
            unit->start = p;
            unit->length = getu32(&p);
            next = p + unit->length;
            unit->version = getu16(&p);
            dwarfDecodeAbbrevs(dwarf, unit,
                    abbrev->sh_offset + obj->fileData + getu32(&p));
            dwarf->addrLen = unit->addrlen = *p++;
            unit->entryPtr = p;
            dwarfDecodeEntries(dwarf, unit, &p, next, &unit->entries);
            unit->end = next;
        }
    }
    *unitp = 0;

    pubunitp = &dwarf->pubnameUnits;
    if (pubnames) {
        for (p = pubnames->sh_offset + obj->fileData, e = p + pubnames->sh_size; p < e; pubunitp = &pubunit->next) {
            pubunit = *pubunitp = elfAlloc(obj, sizeof *pubunit);
            pubunit->length = getu32(&p);
            next = p + pubunit->length;
            pubunit->version = getu16(&p);
            pubunit->infoOffset = getu32(&p);
            pubunit->infoLength = getu32(&p);

            for (pubnamep = &pubunit->pubnames; p < next; pubnamep = &pubname->next) {
                uint32_t offset;
                offset = getu32(&p);
                if (offset == 0)
                    break;
                pubname = *pubnamep = elfAlloc(obj, sizeof *pubname);
                pubname->offset = offset;
                pubname->name = (const char *)p;
                p += strlen((const char *)p) + 1;
            }
            *pubnamep = 0;
            p = next;
        }
    }
    *pubunitp = 0;

    arangep = &dwarf->aranges;
    if (aranges) {
        for (p = start = aranges->sh_offset + obj->fileData, e = p + aranges->sh_size; p < e; arangep = &arange->next, p = next) {
            size_t maxRanges;
            DwarfARange *ranges;
            unsigned align, i;
            int tupleLen;

            arange = *arangep = elfAlloc(obj, sizeof *arange);
            arange->length = getu32(&p);
            next = p + arange->length;
            arange->version = getu16(&p);
            arange->debugInfoOffset = getu32(&p);
            arange->addrlen = *p++;
            arange->segdesclen = *p++;
            maxRanges = arange->length / arange->addrlen / 2;

            tupleLen = arange->addrlen * 2;

            align = (tupleLen - (p - start) % tupleLen) % tupleLen;
            if (align)
                p += align;
            arange->ranges = ranges = elfAlloc(obj, sizeof *ranges * maxRanges);
            for (i = 0; i < maxRanges && p < next; i++) {
                ranges[i].start = getuint(&p, arange->addrlen);
                ranges[i].length = getuint(&p, arange->addrlen);
                if (ranges[i].start == 0 && ranges[i].length == 0)
                    break;
            }
            arange->rangeCount = i;
        }
    }
    *arangep = 0;

    return dwarf;
}

const char *
dwarfTagName(enum DwarfTag tag)
{
#define DWARF_TAG(x,y) case x: return #x;
    switch (tag) {
#include "dwarf/tags.h"
    default: return "(unknown)";
    }
#undef DWARF_TAG
}

const char *
dwarfEOpcodeName(enum DwarfLineEOpcode code)
{
#define DWARF_LINE_E(x,y) case x: return #x;
    switch (code) {
#include "dwarf/line_e.h"
    default: return "(unknown)";
    }
#undef DWARF_LINE_E
}

const char *
dwarfSOpcodeName(enum DwarfLineSOpcode code)
{
#define DWARF_LINE_S(x,y) case x: return #x;
    switch (code) {
#include "dwarf/line_s.h"
    default: return "(unknown)";
    }
#undef DWARF_LINE_S
}

const char *
dwarfFormName(enum DwarfForm form)
{
#define DWARF_FORM(x,y) case x: return #x;
    switch (form) {
#include "dwarf/forms.h"
    default: return "(unknown)";
    }
#undef DWARF_FORM
}

const char *
dwarfAttrName(enum DwarfAttrName attr)
{
#define DWARF_ATTR(x,y) case x: return #x;
    switch (attr) {
#include "dwarf/attr.h"
    default: return "(unknown)";
    }
#undef DWARF_ATTR
}

int
dwarfFindFDE(const DwarfFrameInfo *info, uintmax_t addr, const DwarfFDE **fdep)
{
    DwarfFDE *fde;
    if (info == 0)
        return -1;

    for (fde = info->fdeList; fde; fde = fde->next)
	if (fde->iloc <= addr && fde->iloc + fde->irange > addr) {
            *fdep = fde;
            return 0;
        }
    return -1;
}

int
dwarfSourceFromAddr(DwarfInfo *dwarf, uintmax_t addr, const char **file, int *line)
{
    const DwarfUnit *u;
    int i;
    // XXX: Use "arange" table
    for (u = dwarf->units; u; u = u->next) {
        DwarfLineState *matrix = u->lines->matrix;
        for (i = 0; i < u->lines->rows; i++) {
            if (!matrix[i].end_sequence
                && matrix[i].addr <= addr
                && matrix[i + 1].addr > addr) {
                *file = matrix[i].file->name;
                *line = matrix[i].line;
                return 1;
            }
        }
    }
    return 0;
}

static int
dwarfIsArchReg(int regno)
{
#define REGMAP(regno, regname) case regno: return 1;
switch (regno) {
#include "dwarf/archreg.h"
default: return 0;
}
#undef REGMAP

}

static uintmax_t
dwarfGetCFA(Process *proc, struct DwarfInfo *dwarf, const DwarfCallFrame *frame, const DwarfRegisters *regs)
{
    switch (frame->cfaValue.type) {
        case SAME:
        case VAL_OFFSET:
        case VAL_EXPRESSION:
        case REG:
        case UNDEF:
        case ARCH:
            abort();
            break;

        case OFFSET:
            return dwarfGetReg(regs, frame->cfaReg) + frame->cfaValue.u.offset;
        case EXPRESSION: {
            DwarfExpressionStack stack;
            dwarfStackInit(&stack);
            dwarfEvalExpr(proc, dwarf, regs, &stack,
                    frame->cfaValue.u.expression.data,
                    frame->cfaValue.u.expression.data +
                        frame->cfaValue.u.expression.length);
            return dwarfStackPop(&stack);
        }
    }
    return -1;
}

uintmax_t
dwarfUnwind(Process *proc, DwarfRegisters *regs, uintmax_t addr)
{
    const DwarfFDE *fde;
    int i;
    const unsigned char *p;
    DwarfRegisters newRegs;
    DwarfRegisterUnwind *unwind;
    unsigned char reg[sizeof (uintmax_t)];
    DwarfCallFrame frame;
    struct ElfObject *obj;

    if (procFindObject(proc, addr, &obj) != 0)
        return 0;

    if (obj->dwarf == 0)
        return 0;

    addr = elfAddrProc2Obj(obj, addr);
    if (addr == 0)
        return 0;

    if (dwarfFindFDE(obj->dwarf->debugFrame, addr, &fde) != 0
            && dwarfFindFDE(obj->dwarf->ehFrame, addr, &fde) != 0)
        return 0;

    frame = fde->cie->defaultFrame;
    dwarfExecInsns(proc, obj->dwarf, fde->cie, &frame, fde->instructions, fde->end, fde->iloc, addr);

    // Given the registers available, and the state of the call unwind data, calculate the CFA at this point.
    uintmax_t cfa = dwarfGetCFA(proc, obj->dwarf, &frame, regs);

    for (i = 0; i < MAXREG; i++) {
        if (!dwarfIsArchReg(i))
            continue;

        unwind = frame.registers + i;
        switch (unwind->type) {
            case UNDEF:
            case SAME:
                dwarfSetReg(&newRegs, i, dwarfGetReg(regs, i));
                break;
            case OFFSET:
                procReadMem(proc, reg, cfa + unwind->u.offset, obj->dwarf->addrLen);
                p = reg;
                dwarfSetReg(&newRegs, i, getuint(&p, obj->dwarf->addrLen));
                break;
            case REG:
                dwarfSetReg(&newRegs, i, dwarfGetReg(regs, unwind->u.reg));
                break;

            case EXPRESSION: {
                DwarfExpressionStack stack;
                dwarfStackInit(&stack);
                dwarfStackPush(&stack, cfa);
                dwarfEvalExpr(proc, regs, &stack, unwind->u.expression.data, 
                                unwind->u.expression.data + unwind->u.expression.length);
                dwarfSetReg(&newRegs, i, dwarfStackPop(&stack));
                break;
            }
            default:
            case ARCH:
                abort();
                break;
        }
    }
    // XXX: Where is this codified?
    // The CFA is the SP at the call site for this frame.
#ifdef CFA_RESTORE_REGNO
    if (frame.registers[CFA_RESTORE_REGNO].type == UNDEF)
        dwarfSetReg(&newRegs, CFA_RESTORE_REGNO, cfa);
#endif
    memcpy(regs, &newRegs, sizeof newRegs);
    return dwarfGetReg(&newRegs, fde->cie->rar);
}

void
dwarfSetReg(DwarfRegisters *regs, int regno, uintmax_t regval)
{
    regs->reg[regno] = regval;
}

uintmax_t
dwarfGetReg(const DwarfRegisters *regs, int regno)
{
    return regs->reg[regno];
}

DwarfRegisters *
dwarfPtToDwarf(DwarfRegisters *dwarf, const CoreRegisters *sys)
{
#define REGMAP(number, field) dwarf->reg[number] = sys->field;
#include "dwarf/archreg.h"
#undef REGMAP
    return dwarf;
}

const DwarfRegisters *
dwarfDwarfToPt(CoreRegisters *core, const DwarfRegisters *dwarf)
{
#define REGMAP(number, field) core->field = dwarf->reg[number];
#include "dwarf/archreg.h"
#undef REGMAP
    return dwarf;
}
