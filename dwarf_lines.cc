#include "libpstack/dwarf.h"
#include "libpstack/dwarf_reader.h"
#include "libpstack/global.h"
namespace pstack::Dwarf {

namespace {
using EntryFormats = std::vector<std::pair<DW_LNCT, Form>>;
EntryFormats
readEntryFormats(DWARFReader &r) {
    EntryFormats rv;
    auto format_count = r.getu8();
    std::vector<std::pair<DW_LNCT, Form>> entry_formats;
    for (int i = 0; i < format_count; ++i) {
        DW_LNCT typeCode = DW_LNCT(r.getuleb128());
        auto formCode = Form(r.getuleb128());
        rv.emplace_back(typeCode, formCode);
    }
    return rv;
}
}

LineState::LineState(LineInfo *li)
    : file{ &li->files[1] }
    , addr { 0 }
    , line { 1 }
    , column { 0 }
    , is_stmt { li->default_is_stmt }
    , basic_block { false }
    , end_sequence { false }
    , prologue_end { false }
    , epilogue_begin { false }
    , isa { 0 }
    , discriminator{ 0 }
{}

static void
dwarfStateAddRow(LineInfo *li, const LineState &state)
{
    li->matrix.push_back(state);
}

void
LineInfo::build(DWARFReader &r, Unit &unit)
{
    auto [ total_length, dwarfLen ] = r.getlength();
    Elf::Off end = r.getOffset() + total_length;

    uint16_t version = r.getu16();
    unsigned char address_size;

    if (version >= 5) {
        address_size = r.getu8();
        // We have no interest in segment selector sizes, so just discard them
        /* segment_selector_size = */ r.getu8();
    } else {
        address_size = ELF_BYTES;
        /* segment_selector_size = ELF_BYTES */;
    }

    Elf::Off header_length = r.getuint(version > 2 ? dwarfLen : 4);
    Elf::Off expectedEnd = header_length + r.getOffset();
    int min_insn_length = r.getu8();

    int maximum_operations_per_instruction = version >= 4 ? r.getu8() : 1; // new in DWARF 4.
    (void)maximum_operations_per_instruction; // XXX: work out what to do with this.

    default_is_stmt = r.getu8() != 0;
    int line_base = r.gets8();
    int line_range = r.getu8();

    opcode_base = r.getu8();
    opcode_lengths.resize(opcode_base);
    for (size_t i = 1; i < opcode_base; ++i)
        opcode_lengths[i] = r.getu8();

    int directories_count;
    if (version >= 5) {
        EntryFormats directoryFormat = readEntryFormats(r);
        directories_count = r.getuleb128();
        while( directories_count-- ) {
            std::string path;
            for (auto &ent : directoryFormat) {
                switch (ent.first) {
                    case DW_LNCT_path: {
                        path = r.readFormString(*unit.dwarf, unit, ent.second);
                        break;
                    }
                    default:{
                        r.readForm(*unit.dwarf, unit, ent.second);
                        *debug << "unexpected LNCT " << ent.first << " in directory table" << std::endl;
                        break;
                    }
                }
            }
            if (path == "") {
                *debug << "no path in directory table entry" << std::endl;
            } else {
                directories.emplace_back(path);
            }
        }
        EntryFormats fileFormat = readEntryFormats(r);
        uintmax_t filecount = r.getuleb128();
        while (filecount--) {
            FileEntry entry;
            for (auto &ent : fileFormat) {
                switch (ent.first) {
                    case DW_LNCT_path:
                        entry.name = r.readFormString(*unit.dwarf, unit, ent.second);
                        break;
                    case DW_LNCT_directory_index:
                        entry.dirindex = r.readFormUnsigned(ent.second);
                        break;
                    default:
                        r.readForm(*unit.dwarf, unit, ent.second);
                        break;
                }
            }
            files.push_back(entry);
        }
    } else {
        directories.emplace_back(".");
        int count;
        for (count = 0;; count++) {
            const auto &s = r.getstring();
            if (s == "")
                break;
            directories.push_back(s);
        }

        files.emplace_back("unknown", 0U, 0U, 0U); // index 0 is special
        for (int count = 1;; count++) {
            char c;
            r.io->readObj(r.getOffset(), &c);
            if (c == 0) {
                r.getu8(); // skip terminator.
                break;
            }
            files.emplace_back(r);
        }
    }

    auto diff = expectedEnd - r.getOffset();
    if (diff != 0) {
        if (verbose > 0)
            *debug << "warning: left " << diff
                << " bytes in line info table of " << *r.io << std::endl;
        r.skip(diff);
    }

    if (r.getOffset() == end)
       return;

    LineState state(this);
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
            state.basic_block = false;

        } else if (c == 0) {
            /* Extended opcode */
            int len = r.getuleb128();
            auto code = LineEOpcode(r.getu8());
            switch (code) {
            case DW_LNE_end_sequence:
                state.end_sequence = true;
                dwarfStateAddRow(this, state);
                state = LineState(this);
                break;
            case DW_LNE_set_address:
                state.addr = r.getuint(address_size);
                break;
            case DW_LNE_set_discriminator:
                state.discriminator = r.getuleb128();
                break;
            default:
                r.skip(len - 1);
                abort();
                break;
            }
        } else {
            /* Standard opcode. */
            auto opcode = LineSOpcode(c);
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
                state.file = &files[r.getuleb128()];
                break;
            case DW_LNS_copy:
                dwarfStateAddRow(this, state);
                state.basic_block = false;
                break;
            case DW_LNS_set_column:
                state.column = r.getuleb128();
                break;
            case DW_LNS_negate_stmt:
                state.is_stmt = !state.is_stmt;
                break;
            case DW_LNS_set_basic_block:
                state.basic_block = true;
                break;
            case DW_LNS_set_prologue_end:
                state.prologue_end = true;
                break;
            case DW_LNS_set_epilogue_begin:
                state.epilogue_begin = true;
                break;
            case DW_LNS_set_isa:
                state.isa = r.getuleb128();
                break;
            default:
                abort();
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

FileEntry::FileEntry(std::string name_, unsigned dirindex_, unsigned lastMod_, unsigned length_)
    : name(std::move(name_))
    , dirindex(dirindex_)
    , lastMod(lastMod_)
    , length(length_)
{
}

FileEntry::FileEntry(DWARFReader &r)
    : name(r.getstring())
    , dirindex(r.getuleb128())
    , lastMod(r.getuleb128())
    , length(r.getuleb128())
{
}
}
