#include "libpstack/elf.h"
#include "libpstack/global.h"
#include "libpstack/dwarf.h"
#include "libpstack/dwarf_reader.h"

namespace pstack::Dwarf {

void
Unit::load()
{
    auto &abbrev { dwarf->elf->getDebugSection(".debug_abbrev", SHT_NULL) };
    DWARFReader abbR(abbrev.io(), abbrevOffset);
    uintmax_t code;
    while ((code = abbR.getuleb128()) != 0)
        abbreviations.emplace(std::piecewise_construct,
                std::forward_as_tuple(code),
                std::forward_as_tuple(abbR));
}

std::string
Unit::strx(size_t idx) {
    if (!dwarf->debugStrOffsets)
        throw Exception() << "no string offsets table, but have strx form";
    // Get the root die, and the string offset base.
    auto base = intmax_t(root().attribute(DW_AT_str_offsets_base));
    auto len = dwarfLen;
    DWARFReader r(dwarf->debugStrOffsets.io(), base + len * idx);
    return dwarf->debugStrings.io()->readString(r.getuint(len));
}

uintmax_t
Unit::addrx(size_t idx) {
    if (!dwarf->debugAddr)
        throw Exception() << "no debug addr table, but have addrx form";
    auto base = intmax_t(root().attribute(DW_AT_addr_base));
    return dwarf->debugAddr.io()->readObj<Elf::Addr>(base + idx * sizeof(Elf::Addr));
}


uintmax_t
Unit::rnglistx(size_t slot) {

    DWARFReader r(dwarf->debugRangelists.io(), 0);
    auto attr = root().attribute(DW_AT_rnglists_base);
    auto base = attr.valid() ? uintmax_t(attr) : 0;

    // We need to parse the first part of the header to get the size of the
    // entries in the table.
    size_t dwarflen;
    auto len = r.getlength(&dwarflen);
    (void)len;
    /*
     * We don't need the rest of the fields:
    auto version = r.getuint(2);
    auto address_size = r.getuint(1);
    auto ss_size = r.getuint(1);
    auto offset_entry_count = r.getuint(4);
    */

    // seek to the entry at base + slot ...
    r.setOffset(base + slot * dwarflen);

    // ...then read and add the base.
    return base + r.getuint(dwarflen);
}



Unit::Unit(const Info *di, DWARFReader &r)
    : abbrevOffset{ 0 }
    , dwarf(di)
    , unitType(DW_UT_compile)
    , offset(r.getOffset())
    , length(r.getlength(&dwarfLen))
    , end(r.getOffset() + length)
    , version(r.getu16())
    , id{}
{
    if (version <= 2) // DWARF Version 2 uses the architecture's address size.
       dwarfLen = ELF_BYTES;
    if (version >= 5) {
        unitType = UnitType(r.getu8());
        switch (unitType) {
        case DW_UT_compile:
        case DW_UT_type:
        case DW_UT_partial:
            r.addrLen = addrlen = r.getu8();
            abbrevOffset = r.getuint(dwarfLen);
            break;
        case DW_UT_skeleton:
        case DW_UT_split_compile:
        case DW_UT_split_type:
            r.addrLen = addrlen = r.getu8();
            abbrevOffset = r.getuint(dwarfLen);
            r.getBytes(sizeof id, id);
            break;
        default:
            abort();
        }
    } else {
        abbrevOffset = r.getuint(version <= 2 ? 4 : dwarfLen);
        r.addrLen = addrlen = r.getu8();
    }
    rootOffset = r.getOffset();
    // we now have enough info to parse the abbreviations and the DIE tree.
}

/*
 * Convert an offset to a raw DIE.
 * Offsets are relative to the start of the DWARF info section, *not* the unit.
 * If the parent is not known, it can be null
 * If we later need to find the parent, it may require scanning the entire
 * DIE tree to do so if we don't know parent's offset when requested.
 */

std::shared_ptr<DIE::Raw>
Unit::offsetToRawDIE(const DIE &parent, Elf::Off offset) {
    if (offset == 0 || offset < this->offset || offset >= this->end)
        return nullptr;

    auto &rawptr = allEntries[offset];
    if (rawptr == nullptr) {
        rawptr = DIE::decode(this, parent, offset);
        // this may still be null, and occupy space in the hash table, but
        // it's harmless, and cheaper than removing the entry.
    }
    return rawptr;
}

/*
 * Convert an offset in the dwarf info to a DIE.
 * If the parent is not known, it can be null
 * If we later need to find the parent, it may require scanning the entire
 * DIE tree to do so if we don't know parent's offset when requested.
 */
DIE
Unit::offsetToDIE(const DIE &parent, Elf::Off offset) {
    if (abbreviations.empty())
        load();
    return DIE(shared_from_this(), offset, offsetToRawDIE(parent, offset));
}

DIE Unit::root() {
   return offsetToDIE(DIE(), rootOffset);
}

std::string
Unit::name()
{
    return root().name();
}

const Macros *
Unit::getMacros()
{
    if (macros == nullptr) {
       const DIE &root_ = root();
       for (auto i : { DW_AT_GNU_macros, DW_AT_macros, DW_AT_macro_info }) {
          auto a = root_.attribute(i);
          if (a.valid()) {
              macros = std::make_unique<Macros>(*dwarf, intmax_t(a), i == DW_AT_macro_info ? 4 : 5);
              return macros.get();
          }
       }
    }
    return macros.get();
}

bool
Unit::sourceFromAddr(Elf::Addr addr, std::vector<std::pair<std::string, int>> &info) {
    DIE d = root();
    if (d.containsAddress(addr) == ContainsAddr::NO)
        return false;
    auto lines = getLines();
    if (lines) {
        for (auto i = lines->matrix.begin(); i != lines->matrix.end(); ++i) {
            if (i->end_sequence)
                continue;
            auto next = i+1;
            if (i->addr <= addr && next->addr > addr) {
                auto &dirname = lines->directories[i->file->dirindex];
                info.emplace_back(verbose ? dirname + "/" + i->file->name : i->file->name, i->line);
                return true;
            }
        }
    }
    return false;
}

const LineInfo *
Unit::getLines()
{
    if (lines != nullptr)
        return lines.get();

    const auto &r = root();
    if (r.tag() != DW_TAG_partial_unit && r.tag() != DW_TAG_compile_unit)
        return nullptr; // XXX: assert?

    auto attr = r.attribute(DW_AT_stmt_list);
    if (!attr.valid())
        return nullptr;

    lines.reset(dwarf->linesAt(intmax_t(attr), *this));
    return lines.get();
}

const Abbreviation *
Unit::findAbbreviation(size_t code) const
{
    auto it = abbreviations.find(code);
    return it != abbreviations.end() ? &it->second : nullptr;
}

const Ranges *
Unit::getRanges(const DIE &die, uintmax_t base) {
    auto &ptr = rangesForOffset[die.offset];
    if (ptr == nullptr)
        ptr.reset(new Ranges(die, base));
    return ptr.get();
}

void
Unit::purge()
{
    allEntries = AllEntries();
    rangesForOffset = decltype(rangesForOffset)();
    macros.reset(nullptr);
}

}
