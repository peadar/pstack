#include "libpstack/dwarf.h"
#include "libpstack/dwarf_reader.h"

namespace pstack::Dwarf {

void
DWARFReader::readForm(const Info &info, Unit &unit, Form form)
{
    switch (form) {
        case DW_FORM_string:
        case DW_FORM_line_strp:
        case DW_FORM_strp:
            readFormString(info, unit, form);
            break;
        case DW_FORM_data16:
            skip(16); // line info uses this for LNCT_MD5
            return;

        default:
            abort();
    }
}

std::string
DWARFReader::readFormString(const Info &dwarf, Unit &unit, Form form)
{
    switch (form) {
        case DW_FORM_string:
            return getstring();
        default:
            abort();
        case DW_FORM_line_strp: {
            auto off = getuint(unit.dwarfLen);
            return dwarf.debugLineStrings.io()->readString(off);
        }
        case DW_FORM_strp: {
            auto off = getuint(unit.dwarfLen);
            return dwarf.debugStrings.io()->readString(off);
        }
        case DW_FORM_strx: {
            size_t off = getuleb128();
            return unit.strx(off);
        }
    }
}

uintmax_t
DWARFReader::readFormUnsigned(Form form)
{
    switch (form) {
        case DW_FORM_udata:
            return getuleb128();
        case DW_FORM_data1:
            return getu8();
        case DW_FORM_data2:
            return getu16();
        case DW_FORM_data4:
            return getu32();
        default:
            abort();
    }
}

intmax_t
DWARFReader::readFormSigned(Form form)
{
    switch (form) {
        default:
            abort();
    }
}

std::pair <Elf::Off, Elf::Off>
DWARFReader::getlength() {
    size_t length = getu32();
    if (length == 0xffffffff) {
        return { getuint(8), 8 };
    }
    if (length >= 0xfffffff0) {
        return { 0, 0 };
    }
    return { length, 4 };
}

}
