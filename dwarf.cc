// vim: expandtab:ts=4:sw=4

#include "libpstack/elf.h"
#include "libpstack/dwarf.h"
#include "libpstack/inflatereader.h"

#include <elf.h>
#include <err.h>
#include <libgen.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <stack>
#include <algorithm>

using std::make_unique;
using std::make_shared;
using std::string;

namespace Dwarf {
class RawDIE {
    RawDIE() = delete;
    RawDIE(const RawDIE &) = delete;
    static void readValue(DWARFReader &, const FormEntry &form, Value &value, Unit *);
    const Abbreviation *type;
    std::vector<Value> values;
    Elf::Off parent; // 0 implies we do not yet know the parent's offset.
    Elf::Off firstChild;
    Elf::Off nextSibling;
public:
    RawDIE(Unit *, DWARFReader &, size_t, Elf::Off parent);
    ~RawDIE();
    friend class Attribute;
    friend class DIE;
    friend class DIEAttributes;
    friend class Unit;
    friend class DIEIter;
};

DIEIter &DIEIter::operator++() {
    currentDIE = currentDIE.nextSibling(parent);
    // if we loaded the child by a direct refrence into the middle of the
    // unit, (and hence didn't know the parent at the time), take the
    // opportunity to update its parent pointer
    if (currentDIE && parent && currentDIE.raw->parent == 0)
        currentDIE.raw->parent = parent.offset;
    return *this;
}

DIEIter::DIEIter(const DIE &first, const DIE & parent_)
    : parent(parent_)
    , currentDIE(first)
{
    // As above, take the opportunity to update the current DIE's parent field
    // if it has not already been decided.
    if (currentDIE && parent && currentDIE.raw->parent == 0)
        currentDIE.raw->parent = parent.offset;
}

uintmax_t
DWARFReader::getuleb128shift(int &shift, bool &msb)
{
    uintmax_t result;
    unsigned char byte;
    for (result = 0, shift = 0;;) {
        io->readObj(off++, &byte);
        result |= uintmax_t(byte & 0x7f) << shift;
        shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }
    msb = (byte & 0x40) != 0;
    return result;
}

Pubname::Pubname(DWARFReader &r, uint32_t offset)
    : offset(offset)
    , name(r.getstring())
{
}

PubnameUnit::PubnameUnit(DWARFReader &r)
{
    length = r.getu32();
    Elf::Off next = r.getOffset() + length;

    version = r.getu16();
    infoOffset = r.getu32();
    infoLength = r.getu32();

    while (r.getOffset() < next) {
        uint32_t offset;
        offset = r.getu32();
        if (offset == 0)
            break;
        pubnames.emplace_back(r, offset);
    }
}

static Reader::csptr
sectionReader(Elf::Object &obj, const char *name, const char *compressedName,
        const Elf::Section **secp = nullptr)
{
    const auto &raw = obj.getSection(name, SHT_PROGBITS);
    if (secp != nullptr)
        *secp = nullptr;
    if (raw) {
        if (secp)
            *secp = &raw;
        return raw.io;
    }
    std::string dwoname = std::string(name) + ".dwo";
    const auto &dwo = obj.getSection(dwoname, SHT_PROGBITS);

    if (dwo) {
        if (secp)
            *secp = &dwo;
        return dwo.io;
    }

    if (compressedName != nullptr) {
        const auto &zraw = obj.getSection(compressedName, SHT_PROGBITS);
        if (zraw) {
#ifdef WITH_ZLIB
            unsigned char sig[12];
            zraw.io->readObj(0, sig, sizeof sig);
            if (memcmp((const char *)sig, "ZLIB", 4) != 0)
                return Reader::csptr();
            uint64_t sz = 0;
            for (size_t i = 4; i < 12; ++i) {
                sz <<= 8;
                sz |= sig[i];
            }
            if (secp)
                *secp = &zraw;
            return make_shared<InflateReader>(sz, OffsetReader(zraw.io, sizeof sig, sz));
#else
            std::clog << "warning: no zlib support to process compressed debug info in "
                << *obj.io << std::endl;
#endif
        }
    }
    return Reader::csptr();
}

Info::Info(Elf::Object::sptr obj, ImageCache &cache_)
    : io(sectionReader(*obj, ".debug_info", ".zdebug_info"))
    , elf(obj)
    , debugStrings(sectionReader(*obj, ".debug_str", ".zdebug_str"))
    , debugLineStrings(sectionReader(*obj, ".debug_line_str", ".zdebug_line_str"))
    , abbrev(sectionReader(*obj, ".debug_abbrev", ".zdebug_abbrev"))
    , rangesh(sectionReader(*obj, ".debug_ranges", ".zdebug_ranges"))
    , strOffsets(sectionReader(*obj, ".debug_str_offsets", ".zdebug_str_offsets"))
    , altImageLoaded(false)
    , imageCache(cache_)
    , pubnamesh(sectionReader(*obj, ".debug_pubnames", ".zdebug_pubnames"))
{
    auto f = [this, &obj](const char *name, const char *zname, FIType ftype) {
        const Elf::Section *sec;
        auto io = sectionReader(*obj, name, zname, &sec);
        if (!io)
            return std::unique_ptr<CFI>();
        try {
            return make_unique<CFI>(this, sec->shdr.sh_addr, io, ftype);
        }
        catch (const Exception &ex) {
            *debug << "can't decode " << name << " for " << *obj->io << ": "
                << ex.what() << "\n";
        }
        return std::unique_ptr<CFI>();
    };
    ehFrame = f(".eh_frame", nullptr, FI_EH_FRAME);
    debugFrame = f(".debug_frame", ".zdebug_frame", FI_DEBUG_FRAME);
}

const Macros *
Unit::getMacros()
{
    if (macros == nullptr) {
        Attribute a = root().attribute(DW_AT_GNU_macros);
        if (!a.valid()) {
            a = root().attribute(DW_AT_macros);
            if (!a.valid()) {
                return nullptr;
            }
        }
        macros = std::make_unique<Macros>(dwarf, intmax_t(a));
    }
    return macros.get();
}

enum DWARF_MACRO_CODE {
#define DWARF_MACRO(name, value) name = value,
#include "libpstack/dwarf/macro.h"
      DW_MACRO_invalid
#undef DWARF_MACRO
};

Macros::Macros(const Info *dwarf, intmax_t offset)
    : debug_line_offset(-1)
{
    auto macrosh = sectionReader(*dwarf->elf, ".debug_macro", ".zdebug_macro");
    if (!macrosh)
        return;
    DWARFReader dr(macrosh, offset);
    version = dr.getu16();

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
    reader = std::make_shared<OffsetReader>(macrosh, dr.getOffset());
}

bool
Macros::visit(const Unit *u, MacroVisitor *visitor) const
{
    auto lineinfo = debug_line_offset != -1 ? u->dwarf->linesAt(debug_line_offset, u) : nullptr;
    DWARFReader dr(reader);
    for (bool done=false; !done; ) {
        auto code = dr.getu8();
        if (verbose > 1)
            *debug << dr.getOffset() - 1 << ": "; // adjust to get offset of code
        switch(code) {
            case DW_MACRO_start_file: {
                auto line = dr.getuleb128();
                auto file = dr.getuleb128();
                if (verbose > 1)
                    *debug << "DW_MACRO_start_file( " << lineinfo->files[file].name << " from line " << line << " )\n";
                auto &fileinfo = lineinfo->files[file];
                if (!visitor->startFile(line, lineinfo->directories[fileinfo.dirindex], fileinfo))
                    return false;
                break;
            }

            case DW_MACRO_import: {
                auto offset = dr.getuint(dwarflen);
                if (verbose > 1)
                    *debug << "DW_MACRO_import( " << offset << " )\n";

                // XXX: "u" is likely not right here, but only makes a
                // difference if the import unit uses unit-relative string
                // offsets, which it can't, reliably. (see DW_MACRO_define_strp below)
                Macros nest(u->dwarf, offset);
                if (!nest.visit(u, visitor))
                    return false;

                break;
            }

            case DW_MACRO_define_strp: {
                auto line = dr.getuleb128();
                auto contentOffset = dr.getuint(dwarflen);
                auto str = u->dwarf->debugStrings->readString( contentOffset );
                if (verbose > 1)
                    *debug << "DW_MACRO_define_strp( " << line << ", " << str << " )\n";
                if (!visitor->define(line, str))
                    return false;
                break;
            }

            case DW_MACRO_define: {
                auto line = dr.getuleb128();
                auto str = dr.getstring();
                if (verbose > 1)
                    *debug << "DW_MACRO_define( " << line << ", " << str << " )\n";
                if (!visitor->define(line, str))
                    return false;
                break;
            }

            case DW_MACRO_undef_strp: {
                auto line = dr.getuleb128();
                auto contentOffset = dr.getuint(dwarflen);
                auto str = u->dwarf->debugStrings->readString( contentOffset );
                if (verbose > 1)
                    *debug << "DW_MACRO_undef_strp( " << line << ", '" << str << "' )\n";
                if (!visitor->undef(line, str))
                    return false;
                break;
            }

            case DW_MACRO_undef: {
                auto line = dr.getuleb128();
                auto str = dr.getstring();
                if (verbose > 1)
                    *debug << "DW_MACRO_undef( " << line << ", '" << str << "' )\n";
                if (!visitor->undef(line, str))
                    return false;
                break;
            }

            case DW_MACRO_end_file:
                if (verbose > 1)
                    *debug << "DW_MACRO_end_file()\n";
                if (!visitor->endFile())
                    return false;
                break;

            case 0:
                if (verbose > 1)
                    *debug << "(end of macros)\n";
                done = true;
                break;
            default:
                // os << "macro entry: " << int(code) << "(" << macro_entry_name(code) << ")\n";
                break;
        }
    }
    return true;
}

const std::list<PubnameUnit> &
Info::pubnames() const
{
    if (pubnamesh) {
        DWARFReader r(pubnamesh);
        while (!r.empty())
            pubnameUnits.emplace_back(r);
        pubnamesh = nullptr;
    }
    return pubnameUnits;
}

Unit::sptr
Info::getUnit(Elf::Off offset) const
{
    auto &ent = units[offset];
    if (ent == nullptr) {
        DWARFReader r(io, offset);
        ent = make_shared<Unit>(this, r);
        if (verbose >= 3)
            *debug << "create unit " << ent->name() << "@" << offset
                      << " in " << *io << "\n";
    }
    return ent;
}

DIE
Info::offsetToDIE(Elf::Off offset) const
{
    // We have the offset of the DIE that we want, and the offsets of some
    // subset of units as the keys of 'units'. We can only find the start of a
    // unit if (a) it's the first unit, (b) we find the end of the one before
    // it, or (c) we get a reference from somewhere else in the debug info.
    // (eg, from aranges). So, without a hit in the aranges data, to find the
    // Unit that contains "offset", we need to find the last unit that has an
    // offset <= the required DIE offset, and walk forward until we find the
    // first unit that has an end > the DIE offset (they can be the same unit)

    auto it = std::upper_bound( units.begin(), units.end(), offset,
            [] (Elf::Off offset, const std::pair<Elf::Off, std::shared_ptr<Unit>> &u)
                { return offset < u.first; });

    // "it" is the first unit with an offset > our DIE offset. Our required
    // Unit is before this in the sequence.
    Elf::Off uOffset;

    if (it != units.begin()) {
        // Theres already at least one unit that has an offset < the desired DIE
        // offset. The highest one is at it - 1. Start searching forward from there.
        --it;
        uOffset = it->first;
    } else {
        // There are either no units, or the first unit has an offset higher
        // than our required DIE offset - start at offset 0.
        uOffset = 0;
    }

    int i = 0;
    for (UnitIterator start(this, uOffset), end; start != end; ++start, ++i) {
        const auto &u = *start;
        if (u->end > offset) {
            // this is the first unit that ends after our required offset -
            // we're done looking
            if (u->offset <= offset) {
                // the unit starts at or before our required offset - the DIE
                // should be in here.
                DIE entry = u->offsetToDIE(DIE(), offset);
                if (entry) {
                    if (verbose > 1)
                        *debug << "search for DIE at " << offset
                                  << " in " << *io
                                  << " started at " << uOffset
                                  << ", found at " << u->offset
                                  << " and took " << i << " iterations\n";
                    return entry;
                }
            }
            break;
        }
    }
    throw Exception() << "DIE not found";
}

Units
Info::getUnits() const
{
    return Units(shared_from_this());
}

void
Info::decodeARangeSet(DWARFReader &r) const {
    Elf::Off start = r.getOffset();
    size_t dwarfLen;

    uint32_t length = r.getlength(&dwarfLen);
    Elf::Off next = r.getOffset() + length;
    uint16_t version = r.getu16();
    (void)version;
    Elf::Off debugInfoOffset = r.getu32();
    uint8_t addrlen = r.getu8();
    if (addrlen == 0)
       addrlen = 1;
    r.addrLen = addrlen;
    uint8_t segdesclen = r.getu8();
    (void)segdesclen;
    assert(segdesclen == 0);
    unsigned tupleLen = addrlen * 2;

    // Align on tupleLen-boundary.
    Elf::Off used = r.getOffset() - start;

    unsigned align = tupleLen - used % tupleLen;;
    r.skip(align);
    while (r.getOffset() < next) {
        Elf::Addr start = r.getuint(addrlen);
        Elf::Addr length = r.getuint(addrlen);
        (*aranges)[start + length] = std::make_pair(length, debugInfoOffset);
    }
}

Unit::sptr
Info::lookupUnit(Elf::Addr addr) const {
    if (aranges == nullptr) {
        aranges.reset(new ARanges());
        auto arangesh = sectionReader(*elf, ".debug_aranges", ".zdebug_aranges");
        if (arangesh != nullptr) {
            DWARFReader r(arangesh);
            while (!r.empty())
                decodeARangeSet(r);
        }
    }
    auto it = aranges->upper_bound(addr);
    if (it != aranges->end() && it->first - it->second.first <= addr)
        return getUnit(it->second.second);

    if (!unitRangesCached) {
        // Clang does not add debug_aranges.  If we fail to find the unit via
        // the aranges, walk through all the units, and check out their
        // DW_AT_range attribute, and fold its content into the aranges data.
        unitRangesCached = true;
        for (auto u : getUnits()) {
            auto root = u->root();
            auto lowpc = root.attribute(DW_AT_low_pc);
            auto highpc = root.attribute(DW_AT_high_pc);
            auto ranges = root.attribute(DW_AT_ranges);
            if (lowpc.valid() && highpc.valid()) {
                (*aranges)[uintmax_t(highpc)] = std::make_pair(uintmax_t(highpc) - uintmax_t(lowpc), u->offset);
            }
            if (ranges.valid()) {
                auto rs = Ranges(ranges);
                for (auto r : rs) {
                    (*aranges)[r.second] = std::make_pair(r.first, u->offset);
                }
            }
        }
    }

    // Try again now we've added all the unit ranges.
    it = aranges->upper_bound(addr);
    if (it != aranges->end() && it->first - it->second.first <= addr)
        return getUnit(it->second.second);
    return nullptr;
}

Info::~Info() = default;

void
Unit::load()
{
    DWARFReader abbR(dwarf->abbrev, abbrevOffset);
    uintmax_t code;

    while ((code = abbR.getuleb128()) != 0)
        abbreviations.emplace(std::piecewise_construct,
                std::forward_as_tuple(code),
                std::forward_as_tuple(abbR));
}

Unit::Unit(const Info *di, DWARFReader &r)
    : abbrevOffset{ 0 }
    , dwarf(di)
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
        case DW_UT_skeleton:
            r.addrLen = addrlen = r.getu8();
            abbrevOffset = r.getuint(dwarfLen);
            break;
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
    topDIEOffset = r.getOffset();
    // we now have enough info to parse the abbreviations and the DIE tree.
}

/*
 * Convert an offset to a raw DIE.
 * Offsets are relative to the start of the DWARF info section, *not* the unit.
 * If the parent is not known, it can be null
 * If we later need to find the parent, it may require scanning the entire
 * DIE tree to do so if we don't know parent's offset when requested.
 */

std::shared_ptr<RawDIE>
Unit::offsetToRawDIE(const DIE &parent, Elf::Off offset) {
    if (offset == 0 || offset < this->offset || offset >= this->end)
        return nullptr;
    auto &rawptr = allEntries[offset];
    if (rawptr == nullptr)
        rawptr = decodeEntry(parent, offset);
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
   return offsetToDIE(DIE(), topDIEOffset);
}

string
Unit::name()
{
    return root().name();
}

Unit::~Unit() = default;

Abbreviation::Abbreviation(DWARFReader &r)
    : tag(Tag(r.getuleb128()))
    , hasChildren(HasChildren(r.getu8()) == DW_CHILDREN_yes)
    , nextSibIdx(-1)
{
    for (size_t i = 0;; ++i) {
        auto name = AttrName(r.getuleb128());
        auto form = Form(r.getuleb128());
        if (name == 0 && form == 0)
            break;
        if (name == DW_AT_sibling)
            nextSibIdx = int(i);
        intmax_t value = (form == DW_FORM_implicit_const) ? r.getsleb128() : 0;
        forms.emplace_back(form, value);
        attrName2Idx[name] = i;
    }
}

AttrName
Attribute::name() const
{
    size_t off = formp - &dieref.raw->type->forms[0];
    for (auto ent : dieref.raw->type->attrName2Idx) {
        if (ent.second == off)
            return ent.first;
    }
    return DW_AT_none;
}

Attribute::operator intmax_t() const
{
    if (!valid())
        return 0;
    switch (formp->form) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_sdata:
    case DW_FORM_udata:
    case DW_FORM_implicit_const:
        return value().sdata;
    case DW_FORM_sec_offset:
        return value().addr;
    default:
        abort();
    }
}

Attribute::operator uintmax_t() const
{
    if (!valid())
        return 0;
    switch (formp->form) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_udata:
    case DW_FORM_implicit_const:
        return value().udata;
    case DW_FORM_addr:
    case DW_FORM_sec_offset:
        return value().addr;
    default:
        abort();
    }
}

Attribute::operator const Ranges&() const
{
    auto val = value().addr;

    Ranges &ranges = dieref.unit->rangesForOffset[val];

    if (!ranges.isNew)
        return ranges;

    ranges.isNew = false;

    if (dieref.unit->version < 5) {
        // DWARF4 units use dwarf_ranges
        DWARFReader reader(dieref.unit->dwarf->rangesh, value().addr);
        for (;;) {
            auto start = reader.getuint(sizeof (Elf::Addr));
            auto end = reader.getuint(sizeof (Elf::Addr));
            if (start == 0 && end == 0)
                break;
            ranges.emplace_back(std::make_pair(start, end));
        }
    } else {
        // DWARF5 units use dwarf_rnglists.
        Elf::Off offset = value().addr;

        // Offset by rnglists_base in the root DIE.
        auto root = dieref.unit->root();
        auto attr = root.attribute(DW_AT_rnglists_base);
        if (attr.valid())
            offset += uintmax_t(attr);

        auto rnglists = sectionReader(*dieref.unit->dwarf->elf,
                                    ".debug_rnglists", ".zdebug_rnglists", nullptr);
        auto addrs = sectionReader(*dieref.unit->dwarf->elf,
                                    ".debug_addr", ".zdebug_addr", nullptr);
        DWARFReader r(rnglists, offset);

        uintmax_t base = 0;
        for (bool done = false; !done;) {
            auto entryType = DW_RLE(r.getu8());
            switch (entryType) {
                case DW_RLE_end_of_list:
                    done = true;
                    break;

                case DW_RLE_base_addressx: {
                    /* auto baseidx = */ r.getuleb128();
                    abort();
                    break;
                }

                case DW_RLE_startx_endx: {
                    /* auto startx = */ r.getuleb128();
                    /* auto endx = */ r.getuleb128();
                    abort();
                    break;
                }

                case DW_RLE_startx_length: {
                    /* auto starti = */ r.getuleb128();
                    /* auto len = */ r.getuleb128();
                    abort();
                    break;
                }

                case DW_RLE_offset_pair: {
                    auto offstart = r.getuleb128();
                    auto offend = r.getuleb128();
                    ranges.emplace_back(offstart + base, offend + base);
                    break;
                }

                case DW_RLE_base_address:
                    base = r.getuint(dieref.unit->addrlen);
                    break;

                case DW_RLE_start_end: {
                    auto start = r.getuint(dieref.unit->addrlen);
                    auto end = r.getuint(dieref.unit->addrlen);
                    ranges.emplace_back(start, end);
                    break;
                }
                case DW_RLE_start_length: {
                    auto start = r.getuint(dieref.unit->addrlen);
                    auto len = r.getuleb128();
                    ranges.emplace_back(start, start + len);
                    break;
                }
                default:
                    abort();
            }
        }
    }
    return ranges;
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
DWARFReader::readForm(const Info *info, const Unit *unit, Form form)
{
    switch (form) {
        case DW_FORM_string:
        case DW_FORM_line_strp:
        case DW_FORM_strp:
            readFormString(info, unit, form);
            break;
        default:
            abort();
    }
}

std::string
DWARFReader::readFormString(const Info *dwarf, const Unit *unit, Form form)
{
    switch (form) {
        case DW_FORM_string:
            return getstring();
        default:
            abort();
        case DW_FORM_line_strp: {
            auto off = getuint(unit->dwarfLen);
            return dwarf->debugLineStrings->readString(off);
        }
        case DW_FORM_strp: {
            auto off = getuint(unit->dwarfLen);
            return dwarf->debugStrings->readString(off);
        }
    }
}

uintmax_t
DWARFReader::readFormUnsigned(const Unit *, Form form)
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
DWARFReader::readFormSigned(const Unit *, Form form)
{
    switch (form) {
        default:
            abort();
    }
}


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

void
LineInfo::build(DWARFReader &r, const Unit *unit)
{
    size_t dwarfLen;
    uint32_t total_length = r.getlength(&dwarfLen);
    Elf::Off end = r.getOffset() + total_length;

    uint16_t version = r.getu16();
    unsigned char address_size;

    if (version >= 5) {
        address_size = r.getu8();
        // We have no interest in segment selector sizes, so just discard them
        /* segment_selector_size = */ r.getu8();
    } else {
        address_size = ELF_BYTES;
        /* segment_selector_size = */ ELF_BYTES;
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
                        path = r.readFormString(unit->dwarf, unit, ent.second);
                        break;
                    }
                    default:{
                        r.readForm(unit->dwarf, unit, ent.second);
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
                        entry.name = r.readFormString(unit->dwarf, unit, ent.second);
                        break;
                    case DW_LNCT_directory_index:
                        entry.dirindex = r.readFormUnsigned(unit, ent.second);
                        break;
                    default:
                        r.readForm(unit->dwarf, unit, ent.second);
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

FileEntry::FileEntry(string name_, unsigned dirindex_, unsigned lastMod_, unsigned length_)
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

Attribute::operator std::string() const
{
    if (!valid())
        return "";
    const Info *dwarf = dieref.unit->dwarf;
    assert(dwarf != nullptr);
    switch (formp->form) {

        case DW_FORM_GNU_strp_alt: {
            const auto &alt = dwarf->getAltDwarf();
            if (!alt)
                return "(alt string table unavailable)";
            auto &strs = alt->debugStrings;
            if (!strs)
                return "(alt string table unavailable)";
            return strs->readString(value().addr);
        }
        case DW_FORM_strp:
            return dwarf->debugStrings->readString(value().addr);

        case DW_FORM_line_strp:
            return dwarf->debugLineStrings->readString(value().addr);

        case DW_FORM_string:
            return dieref.unit->dwarf->io->readString(value().addr);

        case DW_FORM_strx1:
        case DW_FORM_strx2:
        case DW_FORM_strx3:
        case DW_FORM_strx4:
        case DW_FORM_strx: {
            if (!dwarf->strOffsets)
                throw Exception() << "no string offsets table, but have strx form";
            // Get the root die, and the string offset base.
            auto root = die().unit->root();
            auto base = intmax_t(root.attribute(DW_AT_str_offsets_base));
            auto idx = value().addr;
            auto len = die().unit->dwarfLen;
            DWARFReader r(dwarf->strOffsets, base + len * idx);
            return dwarf->debugStrings->readString(r.getuint(len));
        }

        default:
            abort();
    }
}

void
RawDIE::readValue(DWARFReader &r, const FormEntry &forment, Value &value, Unit *unit)
{
    switch (forment.form) {

    case DW_FORM_GNU_strp_alt: {
        value.addr = r.getint(unit->dwarfLen);
        break;
    }

    case DW_FORM_strp:
    case DW_FORM_line_strp:
        value.addr = r.getint(unit->version <= 2 ? 4 : unit->dwarfLen);
        break;

    case DW_FORM_GNU_ref_alt:
        value.addr = r.getuint(unit->dwarfLen);
        break;

    case DW_FORM_addr:
        value.addr = r.getuint(unit->addrlen);
        break;

    case DW_FORM_data1:
        value.udata = r.getu8();
        break;

    case DW_FORM_data2:
        value.udata = r.getu16();
        break;

    case DW_FORM_data4:
        value.udata = r.getu32();
        break;

    case DW_FORM_data8:
        value.udata = r.getuint(8);
        break;

    case DW_FORM_sdata:
        value.sdata = r.getsleb128();
        break;

    case DW_FORM_udata:
        value.udata = r.getuleb128();
        break;

    // offsets in various sections...
    case DW_FORM_strx:
    case DW_FORM_loclistx:
    case DW_FORM_rnglistx:
    case DW_FORM_addrx:
    case DW_FORM_ref_udata:
        value.addr = r.getuleb128();
        break;

    case DW_FORM_strx1:
    case DW_FORM_addrx1:
    case DW_FORM_ref1:
        value.addr = r.getu8();
        break;

    case DW_FORM_strx2:
    case DW_FORM_ref2:
        value.addr = r.getu16();
        break;

    case DW_FORM_addrx3:
    case DW_FORM_strx3:
        value.addr = r.getuint(3);
        break;

    case DW_FORM_strx4:
    case DW_FORM_addrx4:
    case DW_FORM_ref4:
        value.addr = r.getu32();
        break;

    case DW_FORM_ref_addr:
        value.addr = r.getuint(unit->dwarfLen);
        break;

    case DW_FORM_ref8:
        value.addr = r.getuint(8);
        break;

    case DW_FORM_string:
        value.addr = r.getOffset();
        r.getstring();
        break;

    case DW_FORM_block1:
        value.block = new Block();
        value.block->length = r.getu8();
        value.block->offset = r.getOffset();
        r.skip(value.block->length);
        break;

    case DW_FORM_block2:
        value.block = new Block();
        value.block->length = r.getu16();
        value.block->offset = r.getOffset();
        r.skip(value.block->length);
        break;

    case DW_FORM_block4:
        value.block = new Block();
        value.block->length = r.getu32();
        value.block->offset = r.getOffset();
        r.skip(value.block->length);
        break;

    case DW_FORM_exprloc:
    case DW_FORM_block:
        value.block = new Block();
        value.block->length = r.getuleb128();
        value.block->offset = r.getOffset();
        r.skip(value.block->length);
        break;

    case DW_FORM_flag:
        value.flag = r.getu8() != 0;
        break;

    case DW_FORM_flag_present:
        value.flag = true;
        break;

    case DW_FORM_sec_offset:
        value.addr = r.getint(unit->dwarfLen);
        break;

    case DW_FORM_ref_sig8:
        value.signature = r.getuint(8);
        break;

    case DW_FORM_implicit_const:
        value.sdata = forment.value;
        break;

    default:
        value.addr = 0;
        abort();
        break;
    }
}

RawDIE::~RawDIE()
{
    int i = 0;
    for (auto &forment : type->forms) {
        switch (forment.form) {
            case DW_FORM_exprloc:
            case DW_FORM_block:
            case DW_FORM_block1:
            case DW_FORM_block2:
            case DW_FORM_block4:
                delete values[i].block;
                break;
            default:
                break;
        }
        ++i;
    }
}

LineInfo *
Info::linesAt(intmax_t offset, const Unit *unit) const
{
    auto lines = new LineInfo();
    auto lineshdr = sectionReader(*elf, ".debug_line", ".zdebug_line");
    if (lineshdr) {
        DWARFReader r(lineshdr, offset);
        lines->build(r, unit);
    }
    return lines;
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

    lines.reset(dwarf->linesAt(intmax_t(attr), this));
    return lines.get();
}

RawDIE::RawDIE(Unit *unit, DWARFReader &r, size_t abbrev, Elf::Off parent_)
    : type(unit->findAbbreviation(abbrev))
    , values(type->forms.size())
    , parent(parent_)
    , firstChild(0)
    , nextSibling(0)
{
    size_t i = 0;
    for (auto &form : type->forms) {
        readValue(r, form, values[i], unit);
        if (int(i) == type->nextSibIdx)
            nextSibling = values[i].sdata + unit->offset;
        ++i;
    }
    if (type->hasChildren) {
        // If the type has children, last offset read is the first child.
        firstChild = r.getOffset();
    } else {
        nextSibling = r.getOffset(); // we have no children, so next DIE is next sib
        firstChild = 0; // no children.
    }
}

const Abbreviation *
Unit::findAbbreviation(size_t code) const
{
    auto it = abbreviations.find(code);
    return it != abbreviations.end() ? &it->second : nullptr;
}

std::shared_ptr<RawDIE>
Unit::decodeEntry(const DIE &parent, Elf::Off offset)
{
    DWARFReader r(dwarf->io, offset);
    size_t abbrev = r.getuleb128();
    if (abbrev == 0) {
        // If we get to the terminator, then we now know the parent's nextSibling:
        // update it now.
        if (parent)
            parent.raw->nextSibling = r.getOffset();
        return nullptr;
    }
    return std::make_shared<RawDIE>(this, r, abbrev, parent.getOffset());
}

void
Unit::purge()
{
    allEntries = AllEntries();
    abbreviations = Abbreviations();
    rangesForOffset = decltype(rangesForOffset)();
    macros.reset(nullptr);
}

string
Info::getAltImageName() const
{
    auto &section = elf->getSection(".gnu_debugaltlink", 0);
    const auto &name = section.io->readString(0);
    if (name[0] == '/')
        return name;

    // relative - prefix it with dirname of the image
    const auto &exedir = dirname(linkResolve(io->filename()));
    return stringify(exedir, "/", name);
}

Info::sptr
Info::getAltDwarf() const
{
    if (!altImageLoaded) {
        altDwarf = imageCache.getDwarf(getAltImageName());
        altImageLoaded = true;
    }
    if (altDwarf == nullptr)
        throw (Exception() << "no alt-dwarf found");
    return altDwarf;
}

intmax_t
CFI::decodeAddress(DWARFReader &f, int encoding) const
{
    intmax_t base;
    Elf::Off offset = f.getOffset();
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
        base = f.getint(sizeof (Elf::Word));
        break;
    default:
        abort();
        break;
    }

    switch (encoding & 0xf0) {
    case 0:
        break;
    case DW_EH_PE_pcrel:
        base += offset + sectionAddr;
        break;
    }
    return base;
}

Elf::Off
DWARFReader::getlength(size_t *dwarflen)
{
    size_t length = getu32();
    if (length >= 0xfffffff0) {
        switch (length) {
            case 0xffffffff:
                if (dwarflen != nullptr)
                    *dwarflen = 8;
                return getuint(8);
            default:
                return 0;
        }
    } else {
        if (dwarflen != nullptr)
            *dwarflen = 4;
        return length;
    }
}

Elf::Off
CFI::decodeCIEFDEHdr(DWARFReader &r, enum FIType type, Elf::Off *cieOff)
{
    size_t addrLen;
    Elf::Off length = r.getlength(&addrLen);
    if (length == 0)
        return 0;
    Elf::Off idoff = r.getOffset();
    auto id = r.getuint(addrLen);
    if (!isCIE(id))
        *cieOff = type == FI_EH_FRAME ? idoff - id : id;
    else
        *cieOff = -1;
    return idoff + length;
}

bool
CFI::isCIE(Elf::Addr cieid)
{
    return (type == FI_DEBUG_FRAME && cieid == 0xffffffff) || (type == FI_EH_FRAME && cieid == 0);
}

CFI::CFI(Info *info, Elf::Addr addr, Reader::csptr io_, enum FIType type_)
    : dwarf(info)
    , sectionAddr(addr)
    , io(std::move(io_))
    , type(type_)
{
    DWARFReader reader(io);
    // decode in 2 passes: first for CIE, then for FDE
    Elf::Off nextoff;
    for (; !reader.empty();  reader.setOffset(nextoff)) {
        size_t startOffset = reader.getOffset();
        Elf::Off associatedCIE;
        nextoff = decodeCIEFDEHdr(reader, type, &associatedCIE);
        if (nextoff == 0)
            break;
        auto ensureCIE = [this, &reader, nextoff] (Elf::Off offset) {
            // This is in fact a CIE - add it in if we have not seen it yet.
            if (cies.find(offset) != cies.end())
                return;
            cies.emplace(std::piecewise_construct,
                        std::forward_as_tuple(offset),
                        std::forward_as_tuple(this, reader, nextoff));
        };
        if (associatedCIE == Elf::Off(-1)) {
            ensureCIE(startOffset);
        } else {
            // Make sure we have the associated CIE.
            ensureCIE(associatedCIE);
            fdeList.emplace_back(this, reader, associatedCIE, nextoff);
        }
    }
}

const FDE *
CFI::findFDE(Elf::Addr addr) const
{
    for (const auto &fde : fdeList)
        if (fde.iloc <= addr && fde.iloc + fde.irange > addr)
            return &fde;
    return nullptr;
}

bool
sourceFromAddrInUnit(const Unit::sptr &unit, Elf::Addr addr,
        std::vector<std::pair<string, int>> &info) {
    DIE d = unit->root();
    if (d.containsAddress(addr) == ContainsAddr::NO)
        return false;
    auto lines = unit->getLines();
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

std::vector<std::pair<std::string, int>>
Info::sourceFromAddr(uintmax_t addr) const
{
    std::vector<std::pair<string, int>> info;

    const auto &unit = lookupUnit(addr);
    if (unit)
        sourceFromAddrInUnit(unit, Elf::Addr(addr), info);
    return info;
}

CallFrame::CallFrame()
    : cfaReg(0)
    , cfaValue{ .type = UNDEF, .u = { .arch = 0  } }
{
    cfaReg = 0;
    cfaValue.type = UNDEF;
#define REGMAP(number, field) registers[number].type = UNDEF;
#include "libpstack/dwarf/archreg.h"
#undef REGMAP
#ifdef CFA_RESTORE_REGNO
    registers[CFA_RESTORE_REGNO].type = ARCH;
#endif
}

CallFrame
CIE::execInsns(DWARFReader &r, uintmax_t addr, uintmax_t wantAddr) const
{
    std::stack<CallFrame> stack;
    CallFrame frame;

    uintmax_t offset;
    int reg, reg2;

    // default frame for this CIE.
    CallFrame dframe;
    if (addr != 0 || wantAddr != 0) {
        DWARFReader r2(r.io, instructions, end);
        dframe = execInsns(r2, 0, 0);
        frame = dframe;
    }
    while (addr <= wantAddr) {
        if (r.empty())
            return frame;
        uint8_t rawOp = r.getu8();
        reg = rawOp &0x3f;
        auto op = CFAInstruction(rawOp & ~0x3f);
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
            op = CFAInstruction(rawOp & 0x3f);
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
                frame.cfaValue.u.offset = r.getsleb128() * dataAlign;
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

            case DW_CFA_GNU_args_size: {
                r.getsleb128(); // Offset.
                // XXX: We don't do anything with this for the moment.
                break;
            }

            // Can't deal with anything else yet.
            case DW_CFA_GNU_window_save:
            case DW_CFA_GNU_negative_offset_extended:
            default:
                abort();
            }
            break;

        default:
            abort();
            break;
        }
    }
    return frame;
}

FDE::FDE(CFI *fi, DWARFReader &reader, Elf::Off cieOff_, Elf::Off endOff_)
    : end(endOff_)
    , cieOff(cieOff_)
{
    auto &cie = fi->cies[cieOff];
    iloc = fi->decodeAddress(reader, cie.addressEncoding);
    irange = fi->decodeAddress(reader, cie.addressEncoding & 0xf);
    if (!cie.augmentation.empty() && cie.augmentation[0] == 'z') {
        size_t alen = reader.getuleb128();
        while (alen-- != 0)
            augmentation.push_back(reader.getu8());
    }
    instructions = reader.getOffset();
}

CIE::CIE(const CFI *fi, DWARFReader &r, Elf::Off end_)
    : frameInfo(fi)
    , addressEncoding(0)
    , addressSize(ELF_BYTES)
    , segmentSize(0)
    , lsdaEncoding(0)
    , isSignalHandler(false)
    , end(end_)
    , personality(0)
{
    version = r.getu8();
    augmentation = r.getstring();
    if (version >= 4) {
        addressSize = r.getu8();
        segmentSize = r.getu8();
    }
    codeAlign = r.getuleb128();
    dataAlign = r.getsleb128();
    rar = r.getu8();

#if ELF_BITS == 32
    addressEncoding = DW_EH_PE_udata4;
#elif ELF_BITS == 64
    addressEncoding = DW_EH_PE_udata8;
#else
    #error "no default address encoding"
#endif

    bool earlyExit = false;
    Elf::Off endaugdata = r.getOffset();
    for (auto aug : augmentation) {
        switch (aug) {
            case 'z':
                endaugdata = r.getuleb128();
                endaugdata += r.getOffset();
                break;
            case 'P':
                personality = fi->decodeAddress(r, r.getu8());
                break;
            case 'L':
                lsdaEncoding = r.getu8();
                break;
            case 'R':
                addressEncoding = r.getu8();
                break;
            case 'S':
                isSignalHandler = true;
                break;
            case '\0':
                break;
            default:
                *debug << "unknown augmentation '" << aug << "' in "
                    << augmentation << std::endl;
                // The augmentations are in order, so we can't make any sense
                // of the remaining data in the augmentation block
                earlyExit = true;
                break;
        }
        if (earlyExit)
            break;
    }
    if (r.getOffset() != endaugdata) {
        *debug << "warning: " << endaugdata - r.getOffset()
            << " bytes of augmentation ignored" << std::endl;
        r.setOffset(endaugdata);
    }
    instructions = r.getOffset();
    r.setOffset(end);
}

Attribute::operator DIE() const
{
    if (!valid())
        return DIE();

    const Info *dwarf = dieref.unit->dwarf;
    Elf::Off off;
    switch (formp->form) {
        case DW_FORM_ref_addr:
            off = value().addr;
            break;
        case DW_FORM_ref_udata:
        case DW_FORM_ref1:
        case DW_FORM_ref2:
        case DW_FORM_ref4:
        case DW_FORM_ref8:
            off = value().addr + dieref.unit->offset;
            break;
        case DW_FORM_GNU_ref_alt: {
            dwarf = dwarf->getAltDwarf().get();
            if (dwarf == nullptr)
                throw (Exception() << "no alt reference");
            off = value().addr;
            break;
        }
        default:
            abort();
            break;
    }

    // Try this unit first (if we're dealing with the same Info)
    if (dwarf == dieref.unit->dwarf && dieref.unit->offset <= off && dieref.unit->end > off) {
        const auto otherEntry = dieref.unit->offsetToDIE(DIE(), off);
        if (otherEntry)
            return otherEntry;
    }

    // Nope - try other units.
    return dwarf->offsetToDIE(off);
}

static void walk(const DIE & die) { for (auto c : die.children()) { walk(c); } };
Elf::Off
DIE::getParentOffset() const
{
    if (raw->parent == 0 && !unit->isRoot(*this)) {
        // This DIE has a parent, but we did not know where it was when we
        // decoded it. We have to search for the parent in the tree. We could
        // limit our search a bit, but the easiest thing to do is just walk the
        // tree from the root down. (This also fixes the problem for any other
        // dies in the same unit.
        if (verbose)
            *debug << "warning: no parent offset "
                << "for die " << name()
                << " at offset " << offset
                << " in unit " << unit->name()
                << " of " << *unit->dwarf->elf->io
                << ", need to do full walk of DIE tree"
                << std::endl;
        walk(unit->root());
        assert(raw->parent != 0);
    }
    return raw->parent;
}

DIE
DIE::firstChild() const {
    return unit->offsetToDIE(*this, raw->firstChild);
}

DIE
DIE::nextSibling(const DIE &parent) const {

    if (raw->nextSibling == 0) {
        // Need to work out what the next sibling is, and we don't have DW_AT_sibling
        // Run through all our children. decodeEntries will update the
        // parent's (our) nextSibling.
        std::shared_ptr<RawDIE> last = nullptr;
        for (auto &it : children())
            last = it.raw;
        if (last)
            last->nextSibling = 0;
    }
    return unit->offsetToDIE(parent, raw->nextSibling);
}

ContainsAddr
DIE::containsAddress(Elf::Addr addr) const
{
    auto low = attribute(DW_AT_low_pc, true);
    auto high = attribute(DW_AT_high_pc, true);

    if (low.valid() && high.valid()) {
        // Simple case - the DIE has a low and high address. Just see if the
        // addr is in that range
        Elf::Addr start, end;
        switch (low.form()) {
            case DW_FORM_addr:
                start = uintmax_t(low);
                break;
            default:
                abort();
                break;
        }

        switch (high.form()) {
            case DW_FORM_addr:
                end = uintmax_t(high);
                break;
            case DW_FORM_data1:
            case DW_FORM_data2:
            case DW_FORM_data4:
            case DW_FORM_data8:
            case DW_FORM_udata:
                end = start + uintmax_t(high);
                break;
            default:
                abort();
        }
        return start <= addr && end > addr ? ContainsAddr::YES : ContainsAddr::NO;
    }

    // We may have .debug_ranges or .debug_rnglists - see if there's a
    // DW_AT_ranges attr.
    Elf::Addr base = low.valid() ? uintmax_t(low) : 0;
    auto ranges = attribute(DW_AT_ranges, true);
    if (ranges.valid()) {
        // Iterate over the ranges, and see if the address lies inside.
        for (auto &range : Ranges(ranges))
            if (range.first + base <= addr && addr <= range.second + base )
                return ContainsAddr::YES;
        return ContainsAddr::NO;
    }
    return ContainsAddr::UNKNOWN;
}

Attribute
DIE::attribute(AttrName name, bool local) const
{
    auto loc = raw->type->attrName2Idx.find(name);
    if (loc != raw->type->attrName2Idx.end())
        return Attribute(*this, &raw->type->forms.at(loc->second));

    // If we have attributes of any of these types, we can look for other
    // attributes in the referenced entry.
    static std::set<AttrName> derefs = {
        DW_AT_abstract_origin,
        DW_AT_specification
    };

    // don't dereference declarations, or any types that provide dereference aliases.
    if (!local && name != DW_AT_declaration && derefs.find(name) == derefs.end()) {
        for (auto alt : derefs) {
            auto ao = DIE(attribute(alt));
            if (ao && ao.raw != raw)
                return ao.attribute(name);
        }
    }
    return Attribute();
}

Info::sptr
ImageCache::getDwarf(const string &filename)
{
    return getDwarf(getImageForName(filename));
}

Info::sptr
ImageCache::getDwarf(Elf::Object::sptr object)
{
    auto it = dwarfCache.find(object);
    dwarfLookups++;
    if (it != dwarfCache.end()) {
        dwarfHits++;
        return it->second;
    }
    auto dwarf = make_shared<Info>(object, *this);
    dwarfCache[object] = dwarf;
    return dwarf;
}

ImageCache::ImageCache() : dwarfHits(0), dwarfLookups(0) { }

ImageCache::~ImageCache() {
    if (verbose >= 2)
        *debug << "DWARF image cache: lookups: " << dwarfLookups << ", hits="
            << dwarfHits << std::endl;
}

void
ImageCache::flush(Elf::Object::sptr o)
{
    Elf::ImageCache::flush(o);
    dwarfCache.erase(o);
}

string
typeName(const DIE &type)
{
    if (!type)
        return "void";

    const auto &name = type.name();
    if (name != "")
        return name;
    auto base = DIE(type.attribute(DW_AT_type));
    string s, sep;
    switch (type.tag()) {
        case DW_TAG_pointer_type:
            return typeName(base) + " *";
        case DW_TAG_const_type:
            return typeName(base) + " const";
        case DW_TAG_volatile_type:
            return typeName(base) + " volatile";
        case DW_TAG_subroutine_type:
            s = typeName(base) + "(";
            sep = "";
            for (auto arg : type.children()) {
                if (arg.tag() != DW_TAG_formal_parameter)
                    continue;
                s += sep;
                s += typeName(DIE(arg.attribute(DW_AT_type)));
                sep = ", ";
            }
            s += ")";
            return s;
        case DW_TAG_reference_type:
            return typeName(base) + "&";
        default: {
            return stringify("(unhandled tag ", type.tag(), ")");
        }
    }
}

DIE
findEntryForAddr(Elf::Addr address, Tag t, const DIE &start, bool skipStart)
{
    switch (start.containsAddress(address)) {
        case ContainsAddr::NO:
            return DIE();
        case ContainsAddr::YES:
            if (!skipStart && start.tag() == t)
                return start;
            /* FALLTHRU */
        case ContainsAddr::UNKNOWN:
            for (auto child : start.children()) {
                auto descendent = findEntryForAddr(address, t, child, false);
                if (descendent)
                    return descendent;
            }
            return DIE();
    }
    return DIE();
}

DIE
findEntryForAddr(Elf::Addr address, Tag t, const DIE &start)
{
    return findEntryForAddr(address, t, start, true);
}

DIEIter
DIEChildren::begin() const {
    return const_iterator(parent.firstChild(), parent);
}

DIEIter
DIEChildren::end() const {
    return const_iterator(DIE(), parent);
}

std::pair<AttrName, Attribute>
DIEAttributes::const_iterator::operator *() const {
    return std::make_pair(
            rawIter->first,
            Attribute(die, &die.raw->type->forms[rawIter->second]));
}

DIEAttributes::const_iterator
DIEAttributes::begin() const {
    return const_iterator(die, die.raw->type->attrName2Idx.begin());
}

DIEAttributes::const_iterator
DIEAttributes::end() const {
    return const_iterator(die, die.raw->type->attrName2Idx.end());
}

const Value &Attribute::value() const {
    return dieref.raw->values.at(formp - &dieref.raw->type->forms[0]);
}

Tag DIE::tag() const {
    return raw->type->tag;
}

bool DIE::hasChildren() const {
    return raw->type->hasChildren;
}

}
