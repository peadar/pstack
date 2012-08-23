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
#include "dump.h"

extern int gVerbose;
static void dwarfDecodeEntries(DWARFReader &r, DwarfUnit *unit, std::list<DwarfEntry *> &list);

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
    for (size_t len = 0;; ++len) {
        char c;
        io.readObj(off, &c);
        off += 1;
        if (c == 0)
            break;
        s << c;
        if (len > 2000)
            abort();
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


DwarfPubname::DwarfPubname(DWARFReader &r, uint32_t offset)
    : offset(offset)
    , name(r.getstring())
{
}

DwarfPubnameUnit::DwarfPubnameUnit(DWARFReader &r)
{
    length = r.getu32();
    Elf_Off next = r.getOffset() + length;

    version = r.version = r.getu16();
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

    // Load all sections we're interested in.
    for (loadsectsp = loadsects; loadsectsp->name; loadsectsp++)
        *loadsectsp->header = obj->findSectionByName(loadsectsp->name);

    // want these first: other sections refer into this.
    if (debstr) {
        debugStrings = new char[debstr->sh_size];
        elf->io.readObj(debstr->sh_offset, debugStrings, debstr->sh_size);
    } else {
        debugStrings = 0;
    }

    if (info) {
        DWARFReader reader(*this, info->sh_offset, info->sh_size);
        while (!reader.empty()) {
            auto unit = new DwarfUnit(reader);
            version = reader.version = unit->version;
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
    version = r.version = r.getu16();
    debugInfoOffset = r.getu32();
    r.addrLen = addrlen = r.getu8();
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
    version = r.version = r.getu16();

    off_t off = version >= 3 ? r.getuint(ELF_BITS/8) : r.getu32();
    DWARFReader abbR(r.dwarf, r.dwarf.abbrev->sh_offset + off, r.dwarf.abbrev->sh_size);
    r.addrLen = addrlen = r.getu8();
    uintmax_t code;
    while ((code = abbR.getuleb128()) != 0)
        abbreviations[DwarfTag(code)] = new DwarfAbbreviation(abbR, code);

    DWARFReader entriesR(r.dwarf, r.getOffset(), nextoff - r.getOffset());
    assert(nextoff <= r.getLimit());
    dwarfDecodeEntries(entriesR, this, entries);
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
    int version = r.version = r.getu16();
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

    files.push_back(new DwarfFileEntry("unknown", "unknown", 0, 0)); // index 0 is special
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
        std::clog << "warning: left "
            << expectedEnd - r.getOffset()
            << " bytes in line info table of "
            << r.dwarf.elf->io
            << std::endl;

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
        value.string = r.dwarf.debugStrings + r.getint(r.version >= 3 ?  ELF_BITS/8 : 4);
        break;

    case DW_FORM_ref2:
        value.ref2 = r.getu16();
        break;

    case DW_FORM_ref4:
        value.ref4 = r.getu32();
        break;

    case DW_FORM_ref_addr:
        value.ref4 = r.getuint(r.version >= 3 ? ELF_BITS / 8 : 4);
        break;

    case DW_FORM_ref8:
        value.ref8 = r.getuint(8);
        break;

    case DW_FORM_string:
        value.string = strdup(r.getstring().c_str());
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

    type = unit->abbreviations[DwarfTag(code)];

    for (auto spec : type->specs)
        attributes[spec->name] = new DwarfAttribute(r, unit, spec);

    switch (type->tag) {
    case DW_TAG_compile_unit: {
        size_t size = dwarfAttr2Int(attributes[DW_AT_stmt_list]);
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
dwarfDecodeEntries(DWARFReader &r, DwarfUnit *unit, std::list<DwarfEntry *> &entries)
{
    while (!r.empty()) {
        intmax_t code = r.getuleb128();
        if (code == 0)
            return;
        entries.push_back(new DwarfEntry(r, code, unit));
    }
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
typedef std::stack<Elf_Addr> DwarfExpressionStack;

static Elf_Addr
dwarfEvalExpr(const Process &proc, DWARFReader r, const DwarfRegisters *frame, DwarfExpressionStack *stack)
{
    while (!r.empty()) {
        auto op = DwarfExpressionOp(r.getu8());
        switch (op) {
            case DW_OP_deref: {
                intmax_t addr = stack->top(); stack->pop();
                Elf_Addr value;
                proc.readObj(addr, &value);
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
                addr = r.getuint(r.addrLen);
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
                reg = r.getuleb128();
                auto &unwind = frame.registers[reg];
                unwind.type = VAL_EXPRESSION;
                unwind.u.expression.length = r.getuleb128();
                unwind.u.expression.offset = r.getOffset();
                r.skip(unwind.u.expression.length);
                break;
            }

            case DW_CFA_expression: {
                reg = r.getuleb128();
                offset = r.getuleb128();
                auto &unwind = frame.registers[reg];
                unwind.type = EXPRESSION;
                unwind.u.expression.offset = r.getOffset();
                unwind.u.expression.length = offset;
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
DwarfCIE::DwarfCIE(DWARFReader &r, Elf_Off end)
{
    this->end = end;

    version = r.version = r.getu8();
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
            augSize = r.getuleb128();
            Elf_Off endaugdata = r.getOffset() + augSize;
            bool earlyExit = false;
            while (++it != augmentation.end()) {
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
                        std::clog << "unknown augmentation '" << *it << "' in " << augmentation << std::endl;
                        // The augmentations are in order, so we can't make any sense of the remaining data in the
                        // augmentation block
                        earlyExit = true;
                        break;
                }
                if (earlyExit)
                    break;
            }
            if (r.getOffset() != endaugdata) {
                std::clog << "warning: " << endaugdata - r.getOffset()
                    << " bytes of augmentation ignored" << std::endl;
                r.setOffset(endaugdata);
            }
        } else {
            std::clog << "augmentation without length delimiter: " << augmentation << std::endl;
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
    id = r.getuint(version >= 3 ? ELF_BITS/8 : 4);
    if (!isCIE(id) && ciep)
        *ciep = cies[type == FI_EH_FRAME ? idoff - id : id];
    return idoff + length;
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
        if (isCIE(cieid))
            cies[cieoff] = new DwarfCIE(reader, nextoff);
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

Elf_Addr
DwarfInfo::getCFA(const Process &proc, const DwarfCallFrame *frame, const DwarfRegisters *regs)
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
            DWARFReader r(*this, frame->cfaValue.u.expression.offset, frame->cfaValue.u.expression.length);
            dwarfEvalExpr(proc, r, regs, &stack);
            Elf_Addr rv = stack.top();
            stack.pop();
            return rv;
        }
    }
    return -1;
}

Elf_Addr
dwarfUnwind(Process &p, DwarfRegisters *regs, Elf_Addr addr)
{
    int i;
    DwarfRegisters newRegs;
    DwarfRegisterUnwind *unwind;

    ElfObject *obj = p.findObject(addr);
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
    DwarfCallFrame frame = fde->cie->execInsns(r, fde->iloc, addr - 3);

    // Given the registers available, and the state of the call unwind data, calculate the CFA at this point.
    uintmax_t cfa = dwarf->getCFA(p, &frame, regs);

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
                p.readObj(cfa + unwind->u.offset, &reg);
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
                dwarfEvalExpr(p, reader, regs, &stack);
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
