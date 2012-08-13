#include "dwarfdump.h"

static void dwarfDumpCFAInsns(std::ostream &os, DWARFReader &r);


std::ostream &operator << (std::ostream &os, const DwarfFileEntry &fe) {
    return os
        << "{ \"name\": \"" << fe.name << "\""
        << ", \"dir\": \"" << fe.directory << "\""
        << ", \"lastmod\": " << fe.lastMod
        << "}";
}

std::ostream &operator << (std::ostream &os, const DwarfLineState &ls) {
    return os
        << "{ \"file\": " << *ls.file
        << ", \"line\": " << ls.line
        << ", \"addr\": " << ls.addr
        << "}";
}

std::ostream &operator << (std::ostream &os, const DwarfLineInfo &lines) {
    return os << lines.matrix;
}

std::ostream & operator << (std::ostream &os, const DwarfEntry &entry) {
    return os
        << "{ \"type\": " << entry.type->tag
        << ", \"attributes\": " << entry.attributes
        << ", \"children\": " << entry.children
        << " }";
}

std::ostream &operator << (std::ostream &os, const DwarfAttributeSpec &spec) {
    return os
        << "{ \"name\": " << spec.name
        << ", \"form\": " << spec.form
        << "}";
}

std::ostream & operator << (std::ostream &os, const DwarfAbbreviation &abbr) {
    return os
        << " { \"code\": " << abbr.code 
        << " , \"has_children\": " << (abbr.hasChildren ? "true" : "false")
        << " , \"specs\": " << abbr.specs
        << " }";
}

std::ostream &operator << (std::ostream &os, const DwarfUnit &unit) {
    return os
        << " { \"length\":" <<  unit.length
        << " , \"version\":" <<  int(unit.version)
        << " , \"addrlen\":" <<  int(unit.addrlen)
        << " , \"linenumbers\":" << *unit.lines
        << " , \"entries\":" <<  unit.entries
        << " }";
}

std::ostream & operator << (std::ostream &os, const DwarfARange &range) {
    return os 
        << " { \"start\":" << range.start
        << " , \"length\":" << range.length
        << " }";
}

std::ostream & operator << (std::ostream &os, const DwarfARangeSet &ranges) {
    return os 
        << " { \"length\":" << ranges.length
        << " , \"version\":" << int(ranges.version)
        << " , \"addrlen\":" << int(ranges.addrlen)
        << " , \"descrlen\":" <<  int(ranges.segdesclen)
        << " , \"ranges\":" <<  ranges.ranges
        << " }";
}

std::ostream & operator << (std::ostream &os, DwarfTag tag) {
#define DWARF_TAG(x,y) case x: return os << "\"" << #x << "\"";
    switch (tag) {
#include "dwarf/tags.h"
    default: return os << "(unknown)";
    }
#undef DWARF_TAG
}

std::ostream &operator << (std::ostream &os, DwarfLineEOpcode code) {
#define DWARF_LINE_E(x,y) case x: return os << "\"" #x "\"";
    switch (code) {
#include "dwarf/line_e.h"
    default: return os << int(code);
    }
#undef DWARF_LINE_E
}

std::ostream &operator << (std::ostream &os, DwarfForm code) {
#define DWARF_FORM(x,y) case x: return os << #x;
    switch (code) {
#include "dwarf/forms.h"
    default: return os << "(unknown)";
    }
#undef DWARF_FORM
}

std::ostream &operator << (std::ostream &os, DwarfAttrName code) {
#define DWARF_ATTR(x,y) case x: return os <<  #x ;
    switch (code) {
#include "dwarf/attr.h"
    default: return os << int(code);
    }
#undef DWARF_ATTR
}

std::ostream &operator << (std::ostream &os, const DwarfPubname &name) {
    return os
        << " { \"offset\": " << name.offset
        << " , \"name\": " << name.name
        << " }";
}

std::ostream &operator << (std::ostream &os, const DwarfPubnameUnit &unit) {
    return os
        << " { \"length\": " << unit.length
        << " , \"version\": " << unit.version
        << " , \"info offset\": " << unit.infoOffset
        << " , \"info size\":" <<  unit.infoLength
        << " , \"names\": " << unit.pubnames
        << " }";
}

std::ostream &
operator << (std::ostream &os, const DwarfBlock &b)
{
    return os << "[ " << b.offset << ", " << b.length << "]";
}

std::ostream &
operator << (std::ostream &os, const DwarfAttribute &attr)
{
    const DwarfAttributeSpec *type = attr.spec;
    const DwarfValue &value = attr.value;
    os
        << "{ \"name\": \"" << type->name << "\""
        << ", \"form\": \"" << type->form << "\""
        << ", \"value\": ";
    switch (type->form) {
    case DW_FORM_addr: os << value.addr; break;
    case DW_FORM_data1: os << int(value.data1); break;
    case DW_FORM_data2: os << value.data2; break;
    case DW_FORM_data4: os << value.data4; break;
    case DW_FORM_data8: os << value.data8; break;
    case DW_FORM_sdata: os << value.sdata; break;
    case DW_FORM_udata: os << value.udata; break;
    case DW_FORM_string: case DW_FORM_strp: os << "\"" << value.udata << "\""; break;
    case DW_FORM_ref2: os << "\"@" << value.ref2 << "\""; break;
    case DW_FORM_ref4: os << "\"@" << value.ref4 << "\""; break;
    case DW_FORM_ref8: os << "\"@" << value.ref8 << "\""; break;
    case DW_FORM_block1: case DW_FORM_block2: case DW_FORM_block4: case DW_FORM_block: os << value.block; break;
    case DW_FORM_flag: os << (value.flag ? "true" : "false"); break;
    default: throw type->form;
    }
    return os << " }";
}

std::ostream &
operator <<(std::ostream &os, const std::pair<const DwarfInfo &, const DwarfCIE *> &dcie)
{
    os
        << "{ \"version\": " << int(dcie.second->version)
        << ", \"augmentation\": " << dcie.second->augmentation
        << ", \"codeAlign\":" << dcie.second->codeAlign
        << ", \"dataAlign\": " << dcie.second->dataAlign
        << ", \"return address reg\": " << dcie.second->rar
        << ", \"augsize\": " <<  dcie.second->augSize
        << ", \"instrlen\": " << dcie.second->end - dcie.second->instructions
        << ", \"instructions\": ";
    DWARFReader r(dcie.first, dcie.second->instructions, dcie.second->end - dcie.second->instructions);
    dwarfDumpCFAInsns(os, r);
    return os
        << " }";
}

std::ostream &
operator << (std::ostream &os, const std::pair<const DwarfInfo &, const DwarfFDE *> &dfde )
{
    os
        << "{ \"cie\": " << dfde.second->cie
        << ", \"loc\": " << dfde.second->iloc
        << ", \"range: " << dfde.second->irange
        << ", \"auglen\": " << dfde.second->aug.size()
        << ", \"instructions\": ";
    DWARFReader r(dfde.first, dfde.second->instructions, dfde.second->end - dfde.second->instructions);
    dwarfDumpCFAInsns(os, r);
    return os << "}";
}

std::ostream &
operator << (std::ostream &os, const DwarfFrameInfo &info)
{

    os << "{ \"cielist\": [";
    const char *sep = "";
    for (auto cie : info.cies) {
        const std::pair<const DwarfInfo &, const DwarfCIE *> pair = std::make_pair(*info.dwarf, cie.second);
        os << sep << pair;
        sep = ", ";
    }
    os << "], \"fdelist\": [";

    sep = "";
    for (auto fde : info.fdeList) {
        const std::pair<const DwarfInfo &, const DwarfFDE *> p = std::make_pair(*info.dwarf, fde);
        os << sep << p;
        sep = ", ";
    }
    return os << " }";
}

std::ostream &
operator << (std::ostream &os, const DwarfInfo &dwarf) 
{
    os
        << "{ \"units\": " << dwarf.units
        << ", \"pubnameUnits\": " << dwarf.pubnameUnits
        << ", \"aranges\": " << dwarf.aranges;

    if (dwarf.debugFrame)
        os << ", \"debugframe\": " << *dwarf.debugFrame;

    if (dwarf.ehFrame)
        os << ", \"ehFrame\": " << *dwarf.ehFrame;
    return os << "}";
}

static void
dwarfDumpCFAInsn(std::ostream &os, DWARFReader &r)
{
    Elf_Off len;
    Elf_Off off = r.getOffset();
    os
        << "{ \"offset\": " << off
        << ", \"type\": ";
    uint8_t op = r.getu8();
    switch (op >> 6) {
    case 1: os << "\"DW_CFA_advance_loc\"" << ", \"delta\":" << (op & 0x3f); break;
    case 2: os << "\"DW_CFA_offset\"" << ", \"register\": " << (op & 0x3f) << r.getuleb128(); break;
    case 3: os << "\"DW_CFA_restore\"" << ", \"register\": " << (op & 0x3f); break;

    case 0:
        switch (op & 0x3f) {
            case 0x0: os << "\"DW_CFA_nop\""; break;
            case 0x1: os << "\"DW_CFA_set_loc\""
                    << ", \"arg\":"
                    << r.getuint(r.version >= 3 ? r.addrLen : 4); break;
            case 0x2: os << "\"DW_CFA_advance_loc1\"" << ", \"arg\":" << r.getu8(); break;
            case 0x3: os << "\"DW_CFA_advance_loc2\"" << ", \"arg\":" <<  r.getu16(); break;
            case 0x4: os << "\"DW_CFA_advance_loc4\"" << ", \"arg\":" << r.getu32(); break;
            case 0x5: os << "\"DW_CFA_offset_extended\"" << ", \"reg\":" << r.getuleb128() << ", \"arg\":" << r.getuleb128(); break;
            case 0x6: os << "\"DW_CFA_restore_extended\"" << ", \"reg\":" << r.getuleb128(); break;
            case 0x7: os << "\"DW_CFA_undefined\"" << ", \"reg\":" << r.getuleb128(); break;
            case 0x8: os << "\"DW_CFA_same_value\"" << ", \"reg\":" << r.getuleb128(); break;
            case 0x9: os << "\"DW_CFA_register\"" << ", \"reg1\":" << r.getuleb128() << ", \"reg2\":" << r.getuleb128(); break;
            case 0xa: os << "\"DW_CFA_remember_state\""; break;
            case 0xb: os << "\"DW_CFA_restore_state\""; break;
            case 0xc: os << "\"DW_CFA_def_cfa\"" << ", \"reg\":" << r.getuleb128() << ", \"offset\":" << r.getuleb128(); break;
            case 0xd: os << "\"DW_CFA_def_cfa_register\"" << ", \"reg\":" << r.getuleb128(); break;
            case 0xe: os << "\"DW_CFA_def_cfa_offset\"" << ", \"offset\":" << r.getuleb128(); break;

            case 0xf: os << "\"DW_CFA_def_cfa_expression\"" << ", \"len\":" << (len = r.getuleb128());
                r.skip(len);
                break;

            case 0x10: os << "\"DW_CFA_expression\"" << ", \"reg\":" << r.getuleb128() << ", \"length\":" << (len = r.getuleb128());
                r.skip(len);
                break;

            case 0x2e: os << "\"DW_CFA_GNU_args_size\"" << ", \"offset\":" << r.getuleb128(); break;
            case 0x2d: os << "\"DW_CFA_GNU_window_size\""; break;
            case 0x2f: os << "\"DW_CFA_GNU_negative_offset_extended\""; break;
            default: throw "unknown CFA op";
            break;
        }
    }
    os << " }";
}

static void
dwarfDumpCFAInsns(std::ostream &os, DWARFReader &r)
{
    os << "[ ";
    std::string sep = "";
    while (!r.empty()) {
        dwarfDumpCFAInsn(os, r);
        os << sep;
        sep = ", ";
    } 
    os << "]";
}
