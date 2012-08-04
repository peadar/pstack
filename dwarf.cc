#include <stack>
#include <unistd.h>
#include <elf.h>
#include <err.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sstream>
#include <iostream>

#include "procinfo.h"
#include "elfinfo.h"
#include "dwarf.h"

extern int gVerbose;

static void dwarfDumpEntries(FILE *out, int indent, const DwarfInfo *dwarf, const DwarfUnit *unit, const std::list<DwarfEntry *> entries);
static void dwarfDumpEntry(FILE *, int, const DwarfInfo *, const DwarfUnit *,  const DwarfEntry *);
static void dwarfDumpCFAInsns(FILE *f, int indent, DWARFReader &);
static void dwarfDecodeEntries(DWARFReader &r, DwarfUnit *unit, std::list<DwarfEntry *> &list);

class DWARFReader {
    Elf_Off off;
    Elf_Off end;
    uintmax_t getuleb128shift(int *shift, bool &isSigned);
public:
    Reader &io;
    DwarfInfo &dwarf;
    ElfObject &elf;
    
    DWARFReader(DwarfInfo &dwarf_, Elf_Off off_, Elf_Word size_)
        : off(off_)
        , end(off_ + size_)
        , io(dwarf_.elf->io)
        , dwarf(dwarf_)
        , elf(*dwarf.elf)
    {
    }
    uint32_t getu32();
    uint16_t getu16();
    uint8_t getu8();
    int8_t gets8();
    uintmax_t getuint(int size);
    intmax_t getint(int size);
    uintmax_t getuleb128();
    intmax_t getsleb128();
    std::string getstring();
    Elf_Off getOffset() { return off; }
    void setOffset(Elf_Off off_) { off = off_; }
    bool empty() { return off == end; }
    Elf_Off getlength();
    void skip(Elf_Off amount) { off += amount; }
};

uintmax_t
DWARFReader::getuint(int len)
{
    uintmax_t rc = 0;
    int i;
    uint8_t bytes[16];
    if (len > 16)
        throw 999;
    io.readObj(off, bytes, len);
    off += len;
    uint8_t *p = bytes + len;
    for (i = 1; i <= len; i++)
        rc = rc << 8 | p[-i];
    return rc;
}

intmax_t
DWARFReader::getint(int len)
{
    intmax_t rc;
    int i;
    uint8_t bytes[16];
    if (len > 16)
        throw 999;
    io.readObj(off, bytes, len);
    off += len;
    uint8_t *p = bytes + len;
    rc = (p[-1] & 0x80) ? -1 : 0;
    for (i = 1; i <= len; i++)
        rc = rc << 8 | p[-i];
    return rc;
}

uint32_t
DWARFReader::getu32()
{
    unsigned char q[4];
    io.readObj(off, q, 4);
    off += sizeof q;
    return q[0] | q[1] << 8 | q[2] << 16 | q[3] << 24;
}

uint16_t
DWARFReader::getu16()
{
    unsigned char q[2];
    io.readObj(off, q, 2);
    off += sizeof q;
    return q[0] | q[1] << 8;
}

uint8_t
DWARFReader::getu8()
{
    unsigned char q;
    io.readObj(off, &q, 1);
    off++;
    return q;
}

int8_t
DWARFReader::gets8()
{
    int8_t q;
    io.readObj(off, &q, 1);
    off += 1;
    return q;
}

std::string
DWARFReader::getstring()
{
    std::ostringstream s;
    char c;
    for (;;) {
        io.readObj(off, &c);
        off += 1;
        if (c == 0)
            break;
        s << c;
    }
    return s.str();
}

uintmax_t
DWARFReader::getuleb128shift(int *shift, bool &isSigned)
{
    uintmax_t result;
    unsigned char byte;
    for (result = 0, *shift = 0;;) {
        io.readObj(off++, &byte);
        result |= (byte & 0x7f) << *shift;
        *shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }
    isSigned = (byte & 0x40) != 0;
    return result;
}

uintmax_t
DWARFReader::getuleb128()
{
    int shift;
    bool isSigned;
    return getuleb128shift(&shift, isSigned);
}

intmax_t
DWARFReader::getsleb128()
{
    int shift;
    bool isSigned;
    intmax_t result = (intmax_t) getuleb128shift(&shift, isSigned);
    if (isSigned)
        result |= - ((uintmax_t)1 << shift);
    return result;
}

static void
dwarfDumpBlock(FILE *out, int indent, const DwarfBlock *block)
{
    fprintf(out, "%jd bytes\n", block->length);
}

static void
dwarfDumpPubname(FILE *out, int indent, const DwarfPubname *name)
{
    fprintf(out, "%s%x: \"%s\"\n", pad(indent), (unsigned)name->offset, name->name.c_str());
}

static void
dwarfDumpPubnameUnit(FILE *out, int indent, const DwarfPubnameUnit *punit)
{
    fprintf(out, "%slength: %d\n", pad(indent), punit->length);
    fprintf(out, "%sversion: %d\n", pad(indent), punit->version);
    fprintf(out, "%sinfo offset: %d\n", pad(indent), punit->infoOffset);
    fprintf(out, "%sinfo size: %d\n", pad(indent), punit->infoLength);
    fprintf(out, "%snames:\n", pad(indent));
    for (auto name : punit->pubnames)
        dwarfDumpPubname(out, indent + 4, name);
}


DwarfPubname::DwarfPubname(DWARFReader &r, uint32_t offset)
    : offset(offset)
    , name(r.getstring())
{
}

DwarfPubnameUnit::DwarfPubnameUnit(DWARFReader &r)
{
    length = r.getu32();
    Elf_Off next = r.getOffset() + length;

    version = r.getu16();
    infoOffset = r.getu32();
    infoLength = r.getu32();

    while (r.getOffset() < next) {
        uint32_t offset;
        offset = r.getu32();
        if (offset == 0)
            break;
        pubnames.push_back(new DwarfPubname(r, offset));
    }
}

DwarfInfo::DwarfInfo(struct ElfObject *obj)
    : elf(obj)
    , version(2)
{

    struct {
        const char *name;
        const Elf_Shdr **header;
    } *loadsectsp, loadsects[] = {
        {".eh_frame", &eh_frame },
        {".debug_info", &info },
        {".debug_abbrev", &abbrev },
        {".debug_str", &debstr },
        {".debug_line", &lineshdr },
        {".debug_frame", &debug_frame },
        {".debug_pubnames", &pubnames}, 
        {".debug_aranges", &arangesh}, 
        { 0, 0 }
    };

    addrLen = 
#ifdef __i386__
        4
#endif
#ifdef __amd64__
        8
#endif
    ;

    // Load all sections we're interested in.
    for (loadsectsp = loadsects; loadsectsp->name; loadsectsp++)
        *loadsectsp->header = obj->findSectionByName(loadsectsp->name);

    if (info) {
        DWARFReader reader(*this, info->sh_offset, info->sh_size);
        while (!reader.empty()) {
            auto unit = new DwarfUnit(reader);
            version = unit->version;
            units.push_back(unit);
        }
    }

    if (eh_frame) {
        DWARFReader reader(*this, eh_frame->sh_offset, eh_frame->sh_size);
        ehFrame = new DwarfFrameInfo(version, reader, FI_EH_FRAME);
    } else {
        ehFrame = 0;
    }

    if (debug_frame) {
        DWARFReader reader(*this, debug_frame->sh_offset, debug_frame->sh_size);
        debugFrame = new DwarfFrameInfo(version, reader, FI_DEBUG_FRAME);
    } else {
        debugFrame = 0;
    }

    if (debstr) {
        debugStrings = new char[debstr->sh_size];
        elf->io.readObj(debstr->sh_offset, debugStrings, debstr->sh_size);
    } else {
        debugStrings = 0;
    }

    if (pubnames) {
        DWARFReader r(*this, pubnames->sh_offset, pubnames->sh_size);
        while (!r.empty())
            pubnameUnits.push_back(new DwarfPubnameUnit(r));
    }

    if (arangesh) {
        DWARFReader r(*this, arangesh->sh_offset, arangesh->sh_size);
        while (!r.empty())
            aranges.push_back(new DwarfARangeSet(r));
    }
}

DwarfARangeSet::DwarfARangeSet(DWARFReader &r)
{
    unsigned align, tupleLen;

    Elf_Off start = r.getOffset();

    length = r.getlength();
    Elf_Off next = r.getOffset() + length;
    version = r.getu16();
    debugInfoOffset = r.getu32();
    addrlen = r.getu8();
    segdesclen = r.getu8();
    tupleLen = addrlen * 2;

    // Align on tupleLen-boundary.
    Elf_Off used = r.getOffset() - start;

    align = tupleLen - used % tupleLen;;
    r.skip(align);

    while (r.getOffset() < next) {
        uintmax_t start = r.getuint(addrlen);
        uintmax_t length = r.getuint(addrlen);
        if (start == 0 && length == 0)
            break;
        ranges.push_back(DwarfARange(start, length));
    }
}

DwarfUnit::DwarfUnit(DWARFReader &r)
{
    length = r.getlength();
    Elf_Off nextoff = r.getOffset() + length;
    version = r.getu16();

    off_t off = version >= 3 ? r.getuint(ELF_BITS/8) : r.getu32();
    DWARFReader abbR(r.dwarf, r.dwarf.abbrev->sh_offset + off, r.dwarf.abbrev->sh_size);
    r.dwarf.addrLen = addrlen = r.getu8();
    uintmax_t code;
    while ((code = abbR.getuleb128()) != 0)
        abbreviations[code] = new DwarfAbbreviation(abbR, code);
    dwarfDecodeEntries(r, this, entries);
    r.setOffset(nextoff);
}

DwarfAbbreviation::DwarfAbbreviation(DWARFReader &r, intmax_t code_)
    : code(code_)
{
    tag = DwarfTag(r.getuleb128());
    hasChildren = DwarfHasChildren(r.getu8());
    for (;;) {
        uintmax_t name, form;
        name = r.getuleb128();
        form = r.getuleb128();
        if (name == 0 && form == 0)
            break;
        specs.push_back(new DwarfAttributeSpec(DwarfAttrName(name), DwarfForm(form)));
    }
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

DwarfLineState::DwarfLineState(DwarfLineInfo *li)
{
    reset(li);
}

void
DwarfLineState::reset(DwarfLineInfo *li)
{
    addr = 0;
    file = li->files[1];
    line = 1;
    column = 0;
    is_stmt = li->default_is_stmt;
    basic_block = 0;
    end_sequence = 0;
}

static void
dwarfStateAddRow(DwarfLineInfo *li, DwarfLineState &state)
{
    li->matrix.push_back(state);
}

DwarfLineInfo::DwarfLineInfo(DWARFReader &r, const DwarfUnit *unit)
{
    uint32_t total_length = r.getlength();
    Elf_Off end = r.getOffset() + total_length;
    int version = r.getu16();
    Elf_Off prologue_length = r.getuint(version >= 3 ? ELF_BITS / 8 : 4);
    Elf_Off expectedEnd = prologue_length + r.getOffset();
    int min_insn_length = r.getu8();
    default_is_stmt = r.getu8();
    int line_base = r.gets8();
    int line_range = r.getu8();

    size_t opcode_base = r.getu8();
    uint8_t *opcode_lengths = new uint8_t[opcode_base];
    for (size_t i = 0; i < opcode_base; ++i)
        opcode_lengths[i] = r.getu8();

    directories.push_back("(compiler CWD)");
    int count;
    for (count = 0;; count++) {
        std::string s = r.getstring();
        if (s == "")
            break;
        directories.push_back(s);
    }

    files.push_back(new DwarfFileEntry("unknown", "unknown", 0, 0));
    for (count = 1;; count++) {
        char c;
        r.io.readObj(r.getOffset(), &c);
        if (c == 0) {
            r.getu8(); // skip terminator.
            break;
        }
        files.push_back(new DwarfFileEntry(r, this));
    }
    if (r.getOffset() != expectedEnd)
        std::clog << "have " << expectedEnd - r.getOffset() << " bytes left\n";

    DwarfLineState state(this);
    while (r.getOffset() < end) {
        unsigned c = r.getu8();
        if (c >= opcode_base) {
            /* Special opcode */
            c -= opcode_base;
            int addrIncr = c / line_range;
            int lineIncr = c % line_range + line_base;
            state.addr += addrIncr * min_insn_length;
            state.line += lineIncr;
            dwarfStateAddRow(this, state);
            state.basic_block = 0;

        } else if (c == 0) {
            /* Extended opcode */
            int len = r.getuleb128();
            enum DwarfLineEOpcode code = DwarfLineEOpcode(r.getu8());
            switch (code) {
            case DW_LNE_end_sequence:
                state.end_sequence = 1;
                dwarfStateAddRow(this, state);
                state.reset(this);
                break;
            case DW_LNE_set_address:
                state.addr = r.getuint(unit->addrlen);
                break;
            case DW_LNE_set_discriminator:
                r.getuleb128(); // XXX: what's this?
                break;
            default:
                r.skip(len - 1);
                abort();
                break;
            }
        } else {
            /* Standard opcode. */
            enum DwarfLineSOpcode opcode = DwarfLineSOpcode(c);
            int argCount, i;
            switch (opcode) {
            case DW_LNS_const_add_pc:
                state.addr += ((255 - opcode_base) / line_range) * min_insn_length;
                break;
            case DW_LNS_advance_pc:
                state.addr += r.getuleb128() * min_insn_length;
                break;
            case DW_LNS_fixed_advance_pc:
                state.addr += r.getu16() * min_insn_length;
                break;
            case DW_LNS_advance_line:
                state.line += r.getsleb128();
                break;
            case DW_LNS_set_file:
                state.file = files[r.getuleb128()];
                break;
            case DW_LNS_copy:
                dwarfStateAddRow(this, state);
                state.basic_block = 0;
                break;
            case DW_LNS_set_column:
                state.column = r.getuleb128();
                break;
            case DW_LNS_negate_stmt:
                state.is_stmt = !state.is_stmt;
                break;
            case DW_LNS_set_basic_block:
                state.basic_block = 1;
                break;
            default:
                argCount = opcode_lengths[opcode - 1];
                for (i = 0; i < argCount; i++)
                    r.getuleb128();
                break;
            case DW_LNS_none:
                break;
            }
        }
    }
}


DwarfFileEntry::DwarfFileEntry(std::string name_, std::string dir_, unsigned lastMod_, unsigned length_)
    : name(name_)
    , directory(dir_)
    , lastMod(lastMod_)
    , length(length_)
{
}

DwarfFileEntry::DwarfFileEntry(DWARFReader &r, DwarfLineInfo *info)
    : name(r.getstring())
    , directory(info->directories[r.getuleb128()])
    , lastMod(r.getuleb128())
    , length(r.getuleb128())
{
}



DwarfAttribute::DwarfAttribute(DWARFReader &r, DwarfUnit *unit, DwarfAttributeSpec *spec_)
    : spec(spec_)
{
    switch (spec->form) {
    case DW_FORM_addr:
        value.addr = r.getuint(unit->addrlen);
        break;

    case DW_FORM_data1:
        value.data1 = r.getu8();
        break;

    case DW_FORM_data2:
        value.data2 = r.getu16();
        break;

    case DW_FORM_data4:
        value.data4 = r.getu32();
        break;

    case DW_FORM_data8:
        value.data8 = r.getuint(8);
        break;

    case DW_FORM_sdata:
        value.sdata = r.getsleb128();
        break;

    case DW_FORM_udata:
        value.udata = r.getuleb128();
        break;

    case DW_FORM_strp:
        value.string = r.dwarf.debugStrings + r.getu32();
        break;

    case DW_FORM_ref2:
        value.ref2 = r.getu16();
        break;

    case DW_FORM_ref4:
        value.ref4 = r.getu32();
        break;

    case DW_FORM_ref8:
        value.ref8 = r.getuint(8);
        break;

    case DW_FORM_string:
        value.string = r.getstring().c_str();
        break;

    case DW_FORM_block1:
        value.block.length = r.getu8();
        value.block.offset = r.getOffset();
        r.skip(value.block.length);
        break;

    case DW_FORM_block2:
        value.block.length = r.getu16();
        value.block.offset = r.getOffset();
        r.skip(value.block.length);
        break;

    case DW_FORM_block4:
        value.block.length = r.getu32();
        value.block.offset = r.getOffset();
        r.skip(value.block.length);
        break;

    case DW_FORM_block:
        value.block.length = r.getuleb128();
        value.block.offset = r.getOffset();
        r.skip(value.block.length);
        break;

    case DW_FORM_flag:
        value.flag = r.getu8();
        break;

    default:
        abort();
        break;
    }
}

DwarfEntry::DwarfEntry(DWARFReader &r, intmax_t code, DwarfUnit *unit)
{

    type = unit->abbreviations[code];

    for (auto spec : type->specs)
        attributes[spec->name] = new DwarfAttribute(r, unit, spec);

    size_t size;
    switch (type->tag) {
    case DW_TAG_compile_unit: {
        size = dwarfAttr2Int(attributes[DW_AT_stmt_list]);
        DWARFReader r2(r.dwarf, r.dwarf.lineshdr->sh_offset + size, r.dwarf.lineshdr->sh_size - size);
        unit->lines = new DwarfLineInfo(r2, unit);
        break;
    }
    default: // not otherwise interested for the mo.
        break;
    }
    if (type->hasChildren)
        dwarfDecodeEntries(r, unit, children);
}

static void
dwarfDecodeEntries(DWARFReader &r, DwarfUnit *unit, std::list<DwarfEntry *> &list)
{
    while (!r.empty()) {
        intmax_t code = r.getuleb128();
        if (code)
            list.push_back(new DwarfEntry(r, code, unit));
    }
}

static void
dwarfDumpAttributes(FILE *out, int indent, const std::map<DwarfAttrName, DwarfAttribute *> &attrs)
{
    for (auto &i : attrs) {
        DwarfAttribute *attr = i.second;
        DwarfAttributeSpec *type = attr->spec;
        const DwarfValue *value = &attr->value;
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
    const DwarfLineInfo *pl = unit->lines;
    for (auto &row : pl->matrix) {
        printf("%s%s (in %s):%d: 0x%jx\n", pad(indent + 4), 
                row.file->name.c_str(),
                row.file->directory.c_str(),
                row.line,
                row.addr);
        if (row.end_sequence)
            printf("\n");
    }
}

static void
dwarfDumpEntry(FILE *out, int indent, const DwarfInfo *dwarf, const DwarfUnit *unit, const DwarfEntry *entry)
{
    fprintf(stdout, "%sEntry type=%s {\n", pad(indent), dwarfTagName(entry->type->tag));
    switch (entry->type->tag) {
    case DW_TAG_compile_unit:
    default:
        break;
    }
    dwarfDumpAttributes(out, indent + 4, entry->attributes);
    if (entry->children.size() > 0) {
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
    fprintf(out, "%s%ju: %s %s\n", pad(indent), abb->code, dwarfTagName(abb->tag), abb->hasChildren ? "(has children)" : "");
    for (auto spec : abb->specs)
        dwarfDumpSpec(out, indent + 4, spec);
}

static void
dwarfDumpEntries(FILE *out, int indent, const DwarfInfo *dwarf, const
                    DwarfUnit *unit, const std::list<DwarfEntry *> entries)
{
    for (auto entry : entries)
        dwarfDumpEntry(out, indent, dwarf, unit, entry);
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
    fprintf(out, "%slength: %d\n", pad(indent), (int)ranges->length);
    fprintf(out, "%sversion: %d\n", pad(indent), (int)ranges->version);
    fprintf(out, "%saddrlen: %d\n", pad(indent), (int)ranges->addrlen);
    fprintf(out, "%sdescrlen: %d\n", pad(indent), (int)ranges->segdesclen);
    for (size_t i = 0; i < ranges->ranges.size(); i++)
        fprintf(out, "%s0x%jx + 0x%jx = 0x%jx\n", pad(indent),
            ranges->ranges[i].start, ranges->ranges[i].length,
            ranges->ranges[i].start + ranges->ranges[i].length);

}

static void
dwarfDumpCIE(FILE *out, int indent, DwarfInfo *dwarf, const DwarfCIE *cie)
{
    fprintf(out, "%sCIE %p {\n", pad(indent), cie);
    fprintf(out, "%sversion: %d\n", pad(indent + 4), cie->version);
    fprintf(out, "%saugmentation: \"%s\"\n", pad(indent + 4), cie->augmentation.c_str());
    fprintf(out, "%scodeAlign: %u\n", pad(indent + 4), cie->codeAlign);
    fprintf(out, "%sdataAlign: %d\n", pad(indent + 4), cie->dataAlign);
    fprintf(out, "%sreturn address reg: %d\n", pad(indent + 4), cie->rar);
    fprintf(out, "%saug size: 0x%lx\n", pad(indent + 4), cie->augSize);

    DWARFReader r(*dwarf, cie->instructions, cie->end - cie->instructions);
    dwarfDumpCFAInsns(out, indent + 4, r);

    fprintf(out, "%s}\n", pad(indent));
}

void
dwarfDumpFDE(FILE *out, int indent, DwarfInfo *dwarf, const DwarfFDE *fde)
{
    fprintf(out, "%sFDE {\n", pad(indent));
    fprintf(out, "%scie: %p\n", pad(indent + 4), fde->cie);
    fprintf(out, "%sloc: 0x%jx\n", pad(indent + 4), fde->iloc);
    fprintf(out, "%srange: 0x%jx\n", pad(indent + 4), fde->irange);
    fprintf(out, "%sauglen: 0x%x\n", pad(indent + 4), (int)fde->aug.size());
    DWARFReader r(*dwarf, fde->instructions, fde->end - fde->instructions);
    dwarfDumpCFAInsns(out, indent + 4, r);
    fprintf(out, "%s}\n", pad(indent));
}

void
dwarfDumpFrameInfo(FILE *out, const DwarfFrameInfo *info, int indent)
{
    for (auto cie : info->cies)
        dwarfDumpCIE(out, indent, info->dwarf, cie.second);
    for (auto fde : info->fdeList)
        dwarfDumpFDE(out, indent, info->dwarf, fde);
}

void
dwarfDump(FILE *out, int indent, const DwarfInfo *dwarf)
{
    int i;

    i = 0;
    for (auto unit : dwarf->units) {
        fprintf(out, "%sTranslationUnit %d {\n", pad(indent), i++);
        dwarfDumpUnit(out, indent + 4, dwarf, unit);
        fprintf(out, "%s}\n", pad(indent));
    }

    i = 0;
    for (auto pubunit : dwarf->pubnameUnits) {
        i++;
        fprintf(out, "%spubname unit %d{\n", pad(indent), i);
        dwarfDumpPubnameUnit(out, indent + 4, pubunit);
        fprintf(out, "%s}\n", pad(indent));
    }

    i = 0;
    for (auto arange : dwarf->aranges) {
        fprintf(out, "%sarange set %d {\n", pad(indent), i++);
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

static void
dwarfDumpCFAInsns(FILE *out, int indent, DWARFReader &r)
{
    uint16_t u16;
    uint32_t u32;
    uintmax_t reg, reg2, offset;
    uintmax_t loc = 0;

    fprintf(out, "%sCFA instructions@%lx {\n", pad(indent), r.getOffset());
    indent += 4;
    while (!r.empty()) {
        uint8_t op = r.getu8();
        uint8_t u8;
        switch (op >> 6) {
        case 1:
            loc += op & 0x3f;
            fprintf(out, "%sDW_CFA_advance_loc(delta=0x%x cur=0x%jx)\n", pad(indent), op & 0x3f, loc);
            break;
        case 2:
            offset = r.getuleb128();
            fprintf(out, "%sDW_CFA_offset(register=0x%x, offset=0x%jx)\n", pad(indent), op & 0x3f, offset);
            break;
        case 3:
            fprintf(out, "%sDW_CFA_restore(register=0x%x)\n", pad(indent), op & 0x3f);
            break;

        case 0:
            switch (op & 0x3f) {
            case 0x0:
                fprintf(out, "%sDW_CFA_nop\n", pad(indent));
                break;
            case 0x1:
                offset = loc = r.getuint(r.dwarf.addrLen);
                fprintf(out, "%sDW_CFA_set_loc(0x%jx, cur=%jx)\n", pad(indent), offset, loc);
                break;
            case 0x2:
                u8 = r.getu8();
                loc += u8;
                fprintf(out, "%sDW_CFA_advance_loc1(delta=0x%x, cur=0x%jx)\n", pad(indent), u8, loc);
                break;
            case 0x3:
                u16 = r.getu16();
                loc += u16;
                fprintf(out, "%sDW_CFA_advance_loc2(delta=0x%x, loc=0x%jx)\n", pad(indent), u16, loc);
                break;
            case 0x4:
                u32 = r.getu32();
                loc += u32;
                fprintf(out, "%sDW_CFA_advance_loc4(delta=0x%x, loc=0x%jx)\n", pad(indent), u32, loc);
                break;
            case 0x5:
                reg = r.getuleb128();
                offset = r.getuleb128();
                fprintf(out, "%sDW_CFA_offset_extended(reg=0x%jx, offset=0x%jx)\n", pad(indent), reg, offset);
                break;
            case 0x6:
                reg = r.getuleb128();
                fprintf(out, "%sDW_CFA_restore_extended(reg=0x%jx)\n", pad(indent), reg);
                break;
            case 0x7:
                reg = r.getuleb128();
                fprintf(out, "%sDW_CFA_undefined(reg=0x%jx)\n", pad(indent), reg);
                break;
            case 0x8:
                reg = r.getuleb128();
                fprintf(out, "%sDW_CFA_same_value(reg=0x%jx)\n", pad(indent), reg);
                break;
            case 0x9:
                reg = r.getuleb128();
                reg2 = r.getuleb128();
                fprintf(out, "%sDW_CFA_register(reg1=0x%jx, reg2=0x%jx)\n", pad(indent), reg, reg2);
                break;
            case 0xa:
                fprintf(out, "%sDW_CFA_remember_state()\n", pad(indent));
                break;
            case 0xb:
                fprintf(out, "%sDW_CFA_restore_state()\n", pad(indent));
                break;
            case 0xc: 
                reg = r.getuleb128();
                offset = r.getuleb128();
                fprintf(out, "%sDW_CFA_def_cfa(reg=0x%jx, offset=0x%jx)\n", pad(indent), reg, offset);
                break;
            case 0xd:
                reg = r.getuleb128();
                fprintf(out, "%sDW_CFA_def_cfa_register(reg=0x%jx)\n", pad(indent), reg);
                break;
            case 0xe:
                offset = r.getuleb128();
                fprintf(out, "%sDW_CFA_def_cfa_offset(offset=0x%jx)\n", pad(indent), offset);
                break;

            case 0xf:
                offset = r.getuleb128();
                fprintf(out, "%sDW_CFA_def_cfa_expression(size=0x%jx)\n", pad(indent), offset);
                r.skip(offset);
                break;

            case 0x10:
                reg = r.getuleb128();
                offset = r.getuleb128();
                fprintf(out, "%sDW_CFA_expression(reg=0x%jx, size=0x%jx)\n", pad(indent), reg, offset);
                r.skip(offset);
                break;

            case 0x2e: // DW_CFA_GNU_args_size
                offset = r.getuleb128();
                fprintf(out, "%sFW_CFA_GNU_args_size(xxx=0x%jx)\n", pad(indent), offset);
                break;

            case 0x2d: // DW_CFA_GNU_window_size
            case 0x2f: // DW_CFA_GNU_negative_offset_extended
            default:
                fprintf(out, "%sDW_CFA_foobar(0x%x)\n", pad(indent), op);
                goto done;
            }
            break;
        }
    }
done:
    indent -= 4;
    fprintf(out, "%s}\n", pad(indent));
}

DwarfCallFrame::DwarfCallFrame()
{
    int i;
    for (i = 0; i < MAXREG; i++)
        registers[i].type = UNDEF;
    cfaReg = 0;
    cfaValue.type = UNDEF;
}


#define STACK_MAX 1024
typedef std::stack<intmax_t> DwarfExpressionStack;

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
dwarfEvalExpr(Process *proc, DWARFReader r, const DwarfRegisters *frame, DwarfExpressionStack *stack)
{
    while (!r.empty()) {
        auto op = DwarfExpressionOp(r.getu8());
        switch (op) {
            case DW_OP_deref: {
                intmax_t addr = stack->top(); stack->pop();
                Elf_Addr value;
                proc->readObj(addr, &value);
                stack->push((intmax_t)(intptr_t)value);
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
                Elf_Off offset = r.getsleb128();
                stack->push(frame->reg[op - DW_OP_breg0] + offset);
                break;
            }

            default: 
                abort();
        }
    }
    intmax_t rv = stack->top();
    stack->pop();
    return rv;
}

DwarfCallFrame
DwarfCIE::execInsns(DWARFReader &r, uintmax_t addr, uintmax_t wantAddr)
{
    std::stack<DwarfCallFrame> stack;
    DwarfCallFrame frame;

    uintmax_t offset;
    int reg, reg2;

    // default frame for this CIE.
    DwarfCallFrame dframe;
    if (addr || wantAddr) {
        DWARFReader r2(r.dwarf, instructions, end - instructions);
        dframe = execInsns(r2, 0, 0);
        frame = dframe;
    }
    while (!r.empty() && addr <= wantAddr) {
        uint8_t rawOp = r.getu8();
        reg = rawOp &0x3f;
        DwarfCFAInstruction op = (DwarfCFAInstruction)(rawOp & ~0x3f);
        switch (op) {
        case DW_CFA_advance_loc:
            addr += reg * codeAlign;
            break;

        case DW_CFA_offset:
            offset = r.getuleb128();
            frame.registers[reg].type = OFFSET;
            frame.registers[reg].u.offset = offset * dataAlign;
            break;

        case DW_CFA_restore: {
            frame.registers[reg] = dframe.registers[reg];
            break;
        }

        case 0:
            op = (DwarfCFAInstruction)(rawOp & 0x3f);
            switch (op) {
            case DW_CFA_nop:
                break;
                
            case DW_CFA_set_loc:
                addr = r.getuint(r.dwarf.addrLen);
                break;

            case DW_CFA_advance_loc1:
                addr += r.getu8() * codeAlign;
                break;

            case DW_CFA_advance_loc2:
                addr += r.getu16() * codeAlign;
                break;

            case DW_CFA_advance_loc4:
                addr += r.getu32() * codeAlign;
                break;

            case DW_CFA_offset_extended:
                reg = r.getuleb128();
                offset = r.getuleb128();
                frame.registers[reg].type = OFFSET;
                frame.registers[reg].u.offset = offset * dataAlign;
                break;

            case DW_CFA_restore_extended:
                reg = r.getuleb128();
                frame.registers[reg] = dframe.registers[reg];
                break;

            case DW_CFA_undefined:
                reg = r.getuleb128();
                frame.registers[reg].type = UNDEF;
                break;

            case DW_CFA_same_value:
                reg = r.getuleb128();
                frame.registers[reg].type = SAME;
                break;

            case DW_CFA_register:
                reg = r.getuleb128();
                reg2 = r.getuleb128();
                frame.registers[reg].type = REG;
                frame.registers[reg].u.reg = reg2;
                break;

            case DW_CFA_remember_state:
                stack.push(frame);
                break;

            case DW_CFA_restore_state:
                frame = stack.top();
                stack.pop();
                break;

            case DW_CFA_def_cfa:
                frame.cfaReg = r.getuleb128();
                frame.cfaValue.type = OFFSET;
                frame.cfaValue.u.offset = r.getuleb128();
                break;

            case DW_CFA_def_cfa_sf:
                frame.cfaReg = r.getuleb128();
                frame.cfaValue.type = OFFSET;
                frame.cfaValue.u.offset = r.getsleb128() * dataAlign;
                break;

            case DW_CFA_def_cfa_register:
                frame.cfaReg = r.getuleb128();
                frame.cfaValue.type = OFFSET;
                break;

            case DW_CFA_def_cfa_offset:
                frame.cfaValue.type = OFFSET;
                frame.cfaValue.u.offset = r.getuleb128();
                break;

            case DW_CFA_def_cfa_offset_sf:
                frame.cfaValue.type = OFFSET;
                frame.cfaValue.u.offset = r.getuleb128() * dataAlign;
                break;

            case DW_CFA_val_expression: {
                DwarfRegisterUnwind *unwind;
                reg = r.getuleb128();
                offset = r.getuleb128();
                unwind = &frame.registers[reg];
                unwind->type = VAL_EXPRESSION;
                unwind->u.expression.offset = r.getOffset();
                unwind->u.expression.length = offset;
                r.skip(offset);
                break;
            }

            case DW_CFA_expression: {
                DwarfRegisterUnwind *unwind;
                reg = r.getuleb128();
                offset = r.getuleb128();
                unwind = &frame.registers[reg];
                unwind->type = EXPRESSION;
                unwind->u.expression.offset = r.getOffset();
                unwind->u.expression.length = offset;
                r.skip(offset);
                break;
            }

            case DW_CFA_def_cfa_expression: {
                frame.cfaValue.type = EXPRESSION;
                offset = r.getuleb128();
                frame.cfaValue.u.expression.length = offset;
                frame.cfaValue.u.expression.offset = r.getOffset();
                r.skip(frame.cfaValue.u.expression.length);
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
    return frame;
}

intmax_t
decodeAddress(DWARFReader &f, int encoding)
{
    intmax_t base;
    Elf_Off offset = f.getOffset();
    switch (encoding & 0xf) {
    case DW_EH_PE_sdata2:
        base = f.getint(2);
        break;
    case DW_EH_PE_sdata4:
        base = f.getint(4);
        break;
    case DW_EH_PE_sdata8:
        base = f.getint(8);
        break;
    case DW_EH_PE_udata2:
        base = f.getuint(2);
        break;
    case DW_EH_PE_udata4:
        base = f.getuint(4);
        break;
    case DW_EH_PE_udata8:
        base = f.getuint(8);
        break;
    case DW_EH_PE_sleb128:
        base = f.getsleb128();
        break;
    case DW_EH_PE_uleb128:
        base = f.getuleb128();
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
        base += offset + f.dwarf.elf->base;
        break;
    }
    return base;
}

DwarfFDE::DwarfFDE(DWARFReader &reader, DwarfCIE *cie_, Elf_Off end_)
    : cie(cie_)
{
    iloc = decodeAddress(reader, cie->addressEncoding);
    irange = decodeAddress(reader, cie->addressEncoding & 0xf);
    if (cie->augmentation.size() != 0 && cie->augmentation[0] == 'z') {
        size_t alen = reader.getuleb128();
        while (alen--)
            aug.push_back(reader.getu8());
    }
    instructions = reader.getOffset();
    end = end_;
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

DwarfCIE::DwarfCIE(DWARFReader &r, Elf_Off end)
{
    this->end = end;

    version = r.getu8();
    augmentation = r.getstring();
    codeAlign = r.getuleb128();
    dataAlign = r.getsleb128();
    rar = r.getu8();

    // Get augmentations...

    augSize = 0;
#if 1 || ELF_BITS == 32
    addressEncoding = DW_EH_PE_udata4;
#elif ELF_BITS == 64
    addressEncoding = DW_EH_PE_udata8;
#else
    #error "no default address encoding"
#endif

    std::string::iterator it = augmentation.begin();
    if (it != augmentation.end()) {
        if (*it == 'z') {
            ++it;
            augSize = r.getuleb128();
            Elf_Off endaugdata = r.getOffset() + augSize;

            for (std::string::iterator augEnd = it + augSize; it < augEnd; ++it) {
                switch (*it) {
                    case 'P': {
                        unsigned char encoding = r.getu8();
                        personality = decodeAddress(r, encoding);
                        break;
                    }
                    case 'L':
                        lsdaEncoding = r.getu8();
                        break;
                    case 'R':
                        addressEncoding = r.getu8();
                        break;
                    case '\0':
                        break;
                    default:
                        fprintf(stderr, "unknown augmentation '%c'\n", *it);
                        // The augmentations are in order, so we can't make any sense of the remaining data in the
                        // augmentation block
                        it = augEnd - 1;
                        break;
                }
            }
            r.setOffset(endaugdata);
        } else {
            fprintf(stderr, "augmentation without length delimiter: '%s'\n", augmentation.c_str());
        }
    }

    instructions = r.getOffset();
    r.setOffset(end);
}

Elf_Off
DWARFReader::getlength()
{

    size_t length = getu32();
    if (length >= 0xfffffff0) {
        switch (length) {
            case 0xffffffff:
                fprintf(stderr, "extended lengh field\n");
                length = getuint(8);
                break;
            default:
                return 0;
        }
    }
    return length;
}

Elf_Off
DwarfFrameInfo::decodeCIEFDEHdr(int version, DWARFReader &r, Elf_Addr &id, enum FIType type, DwarfCIE **ciep)
{
    Elf_Off length = r.getlength();

    if (length == 0)
        return 0;

    Elf_Off idoff = r.getOffset();
    Elf_Off next = idoff + length;
    id = r.getuint(version >= 3 ? ELF_BITS/8 : 4);
    if (!isCIE(id) && ciep)
        *ciep = cies[type == FI_EH_FRAME ? idoff - id : id];
    return next;
}

bool
DwarfFrameInfo::isCIE(Elf_Addr cieid)
{
    return (type == FI_DEBUG_FRAME && cieid == 0xffffffff) || (type == FI_EH_FRAME && cieid == 0);
}

DwarfFrameInfo::DwarfFrameInfo(int version, DWARFReader &reader, enum FIType type_)
    : dwarf(&reader.dwarf)
    , type(type_)
{
    Elf_Addr cieid;

    // decode in 2 passes: first for CIE, then for FDE
    off_t start = reader.getOffset();
    off_t nextoff;
    for (; !reader.empty();  reader.setOffset(nextoff)) {
        size_t cieoff = reader.getOffset();
        nextoff = decodeCIEFDEHdr(version, reader, cieid, type, 0);
        if (nextoff == 0)
            break;
        if (isCIE(cieid)) {
            auto cie = new DwarfCIE(reader, nextoff);
            cies[cieoff] = cie;
        }
    }
    reader.setOffset(start);
    for (reader.setOffset(start); !reader.empty(); reader.setOffset(nextoff)) {
        DwarfCIE *cie;
        nextoff = decodeCIEFDEHdr(version, reader, cieid, type, &cie);
        if (nextoff == 0)
            break;
        if (!isCIE(cieid)) {
            auto fde = new DwarfFDE(reader, cie, nextoff);
            fdeList.push_back(fde);
        }
    }
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

const DwarfFDE *
DwarfFrameInfo::findFDE(Elf_Addr addr) const
{
    for (auto fde : fdeList)
        if (fde->iloc <= addr && fde->iloc + fde->irange > addr)
        return fde;
    return 0;
}

bool
DwarfInfo::sourceFromAddr(uintmax_t addr, std::string &file, int &line)
{
    // XXX: Use "arange" table
    for (auto u : units) {
        auto i = u->lines->matrix.begin();
        auto next = ++i;
        while (next != u->lines->matrix.end()) {
            if (!i->end_sequence && i->addr <= addr && next->addr > addr) {
                file = i->file->name;
                line = i->line;
                return true;
            }
            i = next;
            ++next;
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

static intmax_t
dwarfGetCFA(Process *proc, DwarfInfo *dwarf, const DwarfCallFrame *frame, const DwarfRegisters *regs)
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
            DWARFReader r(*dwarf, frame->cfaValue.u.expression.offset, frame->cfaValue.u.expression.length);
            dwarfEvalExpr(proc, r, regs, &stack);
            intmax_t rv = stack.top();
            stack.pop();
            return rv;
        }
    }
    return -1;
}

uintmax_t
dwarfUnwind(Process *proc, DwarfRegisters *regs, uintmax_t addr)
{
    int i;
    DwarfRegisters newRegs;
    DwarfRegisterUnwind *unwind;

    ElfObject *obj = proc->findObject(addr);
    if (obj == 0)
        return 0;

    DwarfInfo *dwarf = obj->dwarf;

    addr = obj->addrProc2Obj(addr);
    if (addr == 0)
        return 0;

    const DwarfFDE *fde = dwarf->debugFrame ? dwarf->debugFrame->findFDE(addr) : 0;
    if (fde == 0) {
        if (dwarf->ehFrame == 0)
            return 0;
        fde = dwarf->ehFrame->findFDE(addr);
        if (fde == 0)
            return 0;
    }

    DWARFReader r(*dwarf, fde->instructions, fde->end - fde->instructions);
    DwarfCallFrame frame = fde->cie->execInsns(r, fde->iloc, addr);

    // Given the registers available, and the state of the call unwind data, calculate the CFA at this point.
    uintmax_t cfa = dwarfGetCFA(proc, dwarf, &frame, regs);

    for (i = 0; i < MAXREG; i++) {
        if (!dwarfIsArchReg(i))
            continue;

        unwind = frame.registers + i;
        switch (unwind->type) {
            case UNDEF:
            case SAME:
                dwarfSetReg(&newRegs, i, dwarfGetReg(regs, i));
                break;
            case OFFSET: {
                Elf_Addr reg; // XXX: assume addrLen = sizeof Elf_Addr
                proc->readObj(cfa + unwind->u.offset, &reg);
                dwarfSetReg(&newRegs, i, reg);
                break;
            }
            case REG:
                dwarfSetReg(&newRegs, i, dwarfGetReg(regs, unwind->u.reg));
                break;

            case EXPRESSION: {
                DwarfExpressionStack stack;
                stack.push(cfa);
                DWARFReader reader(*dwarf, unwind->u.expression.offset, unwind->u.expression.length);
                dwarfEvalExpr(proc, reader, regs, &stack);
                dwarfSetReg(&newRegs, i, stack.top());
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
