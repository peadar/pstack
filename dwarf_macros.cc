#include "libpstack/dwarf.h"

namespace pstack::Dwarf {
enum DWARF_MACRO_CODE {
#define DWARF_MACRO(name, value) name = value,
#include "libpstack/dwarf/macro.h"
      DW_MACRO_invalid
#undef DWARF_MACRO
};

enum DWARF_MACINFO_CODE {
#define DWARF_MACINFO(name, value) name = value,
#include "libpstack/dwarf/macinfo.h"
#undef DWARF_MACRO
};

std::string
macroName(DWARF_MACRO_CODE code) {
#define DWARF_MACRO(name, value) case name : return #name;
    switch (code) {
#include "libpstack/dwarf/macro.h"
#undef DWARF_MACRO
        default:
          std::ostringstream os;
          os << "unknown macro code" << int(code);
          return os.str();
    }
}

Macros::Macros(const Info &dwarf, intmax_t offset, int version)
    : debug_line_offset(-1)
    , version(version)
{
    if (version >= 5)
        readD5(dwarf, offset);
    else
        readD4(dwarf, offset);
}

void
Macros::readD4(const Info &dwarf, intmax_t offset)
{
    // Legacy dwarf macro information
    auto &macrosh = dwarf.elf->getDebugSection(".debug_macinfo", SHT_NULL);
    if (!macrosh)
        return;
    io = macrosh.io()->view("debug_macinfo subsection", offset);
}

void
Macros::readD5(const Info &dwarf, intmax_t offset)
{
    auto &macrosh = dwarf.elf->getDebugSection(".debug_macro", SHT_NULL);
    if (!macrosh)
        return;
    DWARFReader dr(macrosh.io(), offset);
    // this may report v4, even though .debug_macro did not exist in DWARF 4`
    /* macrosVersion = */ dr.getu16();

    auto flags = dr.getu8();
    auto offset_size_flag = flags & (1<<0);
    dwarflen = offset_size_flag ? 8 : 4;

    auto debug_line_offset_flag = flags & (1<<1);
    auto opcode_operands_table_flag = flags & (1<<2);

    if (debug_line_offset_flag)
        debug_line_offset = dr.getuint(dwarflen);

    if (opcode_operands_table_flag) {
        uint8_t opcode_operand_table_count = dr.getu8();
        for (uint8_t i = 0; i < opcode_operand_table_count; ++i) {
            uint8_t opcode = dr.getu8();
            auto &table = opcodes[opcode];
            auto opcount = dr.getuleb128();
            for (uint8_t j = 0; j < opcount; ++j)
                table.emplace_back(dr.getu8());
        }
    }
    io = macrosh.io()->view("macro subsection", dr.getOffset());
}

bool
Macros::visit(Unit &u, MacroVisitor *visitor) const
{
    if (version >= 5)
        return visit5(u, visitor);
    else
        return visit4(u, visitor);
}

bool
Macros::visit4(Unit &u, MacroVisitor *visitor) const
{
    const auto &lineinfo = u.getLines();
    DWARFReader dr(io);
    for (bool done = false; !done; ) {
        auto code = DWARF_MACINFO_CODE(dr.getu8());
        switch (code) {
            case DW_MACINFO_define: {
                auto line = dr.getuleb128();
                auto text = dr.getstring();
                visitor->define(line, text);
                break;
            }
            case DW_MACINFO_eol: {
                done = true;
                break;
            }
            case DW_MACINFO_undef: {
                auto line = dr.getuleb128();
                auto text = dr.getstring();
                visitor->undef(line, text);
                break;
            }
            case DW_MACINFO_start_file: {
                auto line = dr.getuleb128();
                auto file = dr.getuleb128();
                auto &fileinfo = lineinfo->files[file];
                if (!visitor->startFile(line, lineinfo->directories[fileinfo.dirindex], fileinfo))
                    return false;
                break;
            }
            case DW_MACINFO_end_file: {
                if (!visitor->endFile())
                    return 0;
                break;
            }
            case DW_MACINFO_vendor_ext:
                break;
        }
    }
    return true;
}

bool
Macros::visit5(Unit &u, MacroVisitor *visitor) const
{
    auto lineinfo = debug_line_offset != -1 ? u.dwarf->linesAt(debug_line_offset, u) : nullptr;
    DWARFReader dr(io);
    for (bool done=false; !done; ) {
        auto code = DWARF_MACRO_CODE(dr.getu8());
        if (u.dwarf->elf->context.verbose > 1)
            *u.dwarf->elf->context.debug << dr.getOffset() - 1 << ": "; // adjust to get offset of code
        switch(code) {
            case DW_MACRO_start_file: {
                auto line = dr.getuleb128();
                auto file = dr.getuleb128();
                if (u.dwarf->elf->context.verbose > 1)
                    *u.dwarf->elf->context.debug << "DW_MACRO_start_file( " << lineinfo->files[file].name << " from line " << line << " )\n";
                auto &fileinfo = lineinfo->files[file];
                if (!visitor->startFile(line, lineinfo->directories[fileinfo.dirindex], fileinfo))
                    return false;
                break;
            }

            case DW_MACRO_import: {
                auto offset = dr.getuint(dwarflen);
                if (u.dwarf->elf->context.verbose > 1)
                    *u.dwarf->elf->context.debug << "DW_MACRO_import( " << offset << " )\n";

                // XXX: "u" is likely not right here, but only makes a
                // difference if the import unit uses unit-relative string
                // offsets, which it can't, reliably. (see DW_MACRO_define_strp below)
                Macros nest(*u.dwarf, offset, 5);
                if (!nest.visit(u, visitor))
                    return false;

                break;
            }

            case DW_MACRO_define_strx:
            case DW_MACRO_define_strp: {
                auto line = dr.getuleb128();
                auto str = dr.readFormString(*u.dwarf, u, code == DW_MACRO_define_strx ? DW_FORM_strx : DW_FORM_strp);
                if (u.dwarf->elf->context.verbose > 1)
                    *u.dwarf->elf->context.debug << "DW_MACRO_define_strp( " << line << ", " << str << " )\n";
                if (!visitor->define(line, str))
                    return false;
                break;
            }

            case DW_MACRO_define: {
                auto line = dr.getuleb128();
                auto str = dr.getstring();
                if (u.dwarf->elf->context.verbose > 1)
                    *u.dwarf->elf->context.debug << "DW_MACRO_define( " << line << ", " << str << " )\n";
                if (!visitor->define(line, str))
                    return false;
                break;
            }

            case DW_MACRO_undef_strx:
            case DW_MACRO_undef_strp: {
                auto line = dr.getuleb128();
                auto str = dr.readFormString(*u.dwarf, u, code == DW_MACRO_undef_strx ? DW_FORM_strx : DW_FORM_strp);
                if (u.dwarf->elf->context.verbose > 1)
                    *u.dwarf->elf->context.debug << "DW_MACRO_undef_strp( " << line << ", '" << str << "' )\n";
                if (!visitor->undef(line, str))
                    return false;
                break;
            }

            case DW_MACRO_undef: {
                auto line = dr.getuleb128();
                auto str = dr.getstring();
                if (u.dwarf->elf->context.verbose > 1)
                    *u.dwarf->elf->context.debug << "DW_MACRO_undef( " << line << ", '" << str << "' )\n";
                if (!visitor->undef(line, str))
                    return false;
                break;
            }

            case DW_MACRO_end_file:
                if (u.dwarf->elf->context.verbose > 1)
                    *u.dwarf->elf->context.debug << "DW_MACRO_end_file()\n";
                if (!visitor->endFile())
                    return false;
                break;

            case DW_MACRO_eol:
                if (u.dwarf->elf->context.verbose > 1)
                    *u.dwarf->elf->context.debug << "(end of macros)\n";
                done = true;
                break;

            default:
                *u.dwarf->elf->context.debug << "unhandled macro entry: " << int(code) << "(" << macroName(code) << ")\n";
                break;
        }
    }
    return true;
}

}
