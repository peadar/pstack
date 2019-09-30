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

uintmax_t
DWARFReader::getuleb128shift(int *shift, bool &isSigned)
{
    uintmax_t result;
    unsigned char byte;
    for (result = 0, *shift = 0;;) {
        io->readObj(off++, &byte);
        result |= uintmax_t(byte & 0x7f) << *shift;
        *shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }
    isSigned = (byte & 0x40) != 0;
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
sectionReader(Elf::Object &obj, const char *name, const char *compressedName, const Elf::Section **secp = nullptr)
{
    const auto &raw = obj.getSection(name, SHT_PROGBITS);
    if (secp != nullptr)
        *secp = nullptr;
    if (raw) {
        if (secp)
            *secp = &raw;
        return raw.io;
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
    , abbrev(sectionReader(*obj, ".debug_abbrev", ".zdebug_abbrev"))
    , lineshdr(sectionReader(*obj, ".debug_line", ".zdebug_line"))
    , altImageLoaded(false)
    , imageCache(cache_)
    , pubnamesh(sectionReader(*obj, ".debug_pubnames", ".zdebug_pubnames"))
    , arangesh(sectionReader(*obj, ".debug_aranges", ".zdebug_aranges"))
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
            std::clog << "can't decode " << name << " for " << *obj->io << ": " << ex.what() << "\n";
        }
        return std::unique_ptr<CFI>();
    };
    ehFrame = f(".eh_frame", nullptr, FI_EH_FRAME);
    debugFrame = f(".debug_frame", ".zdebug_frame", FI_DEBUG_FRAME);
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

static size_t UNITCACHE_SIZE=128;

Unit::sptr
UnitsCache::get(const Info *info, off_t offset)
{
    auto &ent = byOffset[offset];
    if (ent != nullptr) {
        auto idx = std::find(LRU.begin(), LRU.end(), ent);
        assert(idx != LRU.end());
        LRU.erase(idx);
    } else {
        DWARFReader r(info->io, offset);
        ent = make_shared<Unit>(info, r);
        if (verbose > 2)
            std::clog << "create unit " << ent->name() << "@" << offset << std::endl;
    }
    LRU.push_front(ent);
    if (LRU.size() > UNITCACHE_SIZE) {
        auto old = LRU.back();
        LRU.pop_back();
        // don't erase from the map - we hold on to the offsets so we can quickly
        // determine which unit contains a particular DIE.
        byOffset[old->offset] = 0;
    }
    return ent;
}

DIE
Info::offsetToDIE(off_t offset) const
{
    // find the appropriate unit for a die with that offset.
    auto it = std::lower_bound(
            units.byOffset.begin(),
            units.byOffset.end(),
            offset,
            [] (const std::pair<off_t, std::shared_ptr<Unit>> &u, off_t offset)

                { return u.first < offset; });
    off_t uOffset;
    if (it == units.byOffset.begin() || it == units.byOffset.end()) {
        uOffset = 0;
    } else {
        --it;
        uOffset = it->first;
    }
    UnitIterator start(this, uOffset);
    UnitIterator end;
    for (int i = 1; start != end; ++start, ++i) {
        const auto &u = *start;
        DIE entry = u->offsetToDIE(offset);
        if (entry) {
            if (verbose > 2)
                std::clog << "search for DIE at " << offset << " started at " << uOffset <<" and took " << i << " iterations\n";
            return entry;
        }
    }
    throw Exception() << "DIE not found";
}

Unit::sptr
Info::getUnit(off_t offset) const
{
    return units.get(this, offset);
}

Units
Info::getUnits() const
{
    return Units(shared_from_this());
}

std::list<ARangeSet> &
Info::getARanges() const
{
    if (arangesh) {
        DWARFReader r(arangesh);
        while (!r.empty())
            aranges.emplace_back(r);
        arangesh = nullptr;
    }
    return aranges;
}

Info::~Info() = default;

ARangeSet::ARangeSet(DWARFReader &r)
{
    unsigned align, tupleLen;
    Elf::Off start = r.getOffset();
    size_t dwarfLen;

    length = r.getlength(&dwarfLen);
    Elf::Off next = r.getOffset() + length;
    version = r.getu16();
    debugInfoOffset = r.getu32();
    addrlen = r.getu8();
    if (addrlen == 0)
       addrlen = 1;
    r.addrLen = addrlen;
    segdesclen = r.getu8();
    tupleLen = addrlen * 2;

    // Align on tupleLen-boundary.
    Elf::Off used = r.getOffset() - start;

    align = tupleLen - used % tupleLen;;
    r.skip(align);

    while (r.getOffset() < next) {
        uintmax_t start = r.getuint(addrlen);
        uintmax_t length = r.getuint(addrlen);
        ranges.emplace_back(start, length);
    }
}

Unit::Unit(const Info *di, DWARFReader &r)
    : dwarf(di)
    , io(r.io)
    , offset(r.getOffset())
    , length(r.getlength(&dwarfLen))
    , end(r.getOffset() + length)
    , version(r.getu16())
{
    if (version <= 2) // DWARF Version 2 uses the architecture's address size.
       dwarfLen = ELF_BITS / 8;
    off_t off = r.getuint(version <= 2 ? 4 : dwarfLen);
    DWARFReader abbR(di->abbrev, off);
    r.addrLen = addrlen = r.getu8();
    uintmax_t code;
    while ((code = abbR.getuleb128()) != 0)
        abbreviations.emplace( std::piecewise_construct,
                std::forward_as_tuple(code),
                std::forward_as_tuple(abbR));
    topDIEOffset = r.getOffset();

    r.setOffset(end);
}

DIE
Unit::offsetToDIE(size_t parentOffset, size_t offset) {
    if (offset == 0)
        return DIE();
    auto it = allEntries.find(offset);
    if (it == allEntries.end())
        it = loadChildDIE(parentOffset, offset);
    return it != allEntries.end() ? DIE(shared_from_this(), offset, &it->second) : DIE();
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
        forms.emplace_back(form);
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
    switch (*formp) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_sdata:
    case DW_FORM_udata:
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
    switch (*formp) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
     case DW_FORM_udata:
        return value().udata;
    case DW_FORM_addr:
    case DW_FORM_sec_offset:
        return value().addr;
    default:
        abort();
    }
}

LineState::LineState(LineInfo *li)
    : addr { 0 }
    , file { &li->files[1] }
    , line { 1 }
    , column { 0 }
    , isa { 0 }
    , is_stmt { li->default_is_stmt }
    , basic_block { false }
    , end_sequence { false }
    , prologue_end { false }
    , epilogue_begin { false }
{}

static void
dwarfStateAddRow(LineInfo *li, const LineState &state)
{
    li->matrix.push_back(state);
}

void
LineInfo::build(DWARFReader &r, const Unit *unit)
{
    size_t dwarfLen;
    uint32_t total_length = r.getlength(&dwarfLen);
    Elf::Off end = r.getOffset() + total_length;

    uint16_t version = r.getu16();
    (void)version;
    Elf::Off header_length = r.getuint(version > 2 ? dwarfLen: 4);
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

    directories.emplace_back(".");
    int count;
    for (count = 0;; count++) {
        const auto &s = r.getstring();
        if (s == "")
            break;
        directories.push_back(s);
    }

    files.emplace_back("unknown", "unknown", 0U, 0U); // index 0 is special
    for (count = 1;; count++) {
        char c;
        r.io->readObj(r.getOffset(), &c);
        if (c == 0) {
            r.getu8(); // skip terminator.
            break;
        }
        files.emplace_back(r, this);
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

FileEntry::FileEntry(string name_, string dir_, unsigned lastMod_, unsigned length_)
    : name(std::move(name_))
    , directory(std::move(dir_))
    , lastMod(lastMod_)
    , length(length_)
{
}

FileEntry::FileEntry(DWARFReader &r, LineInfo *info)
    : name(r.getstring())
    , directory(info->directories[r.getuleb128()])
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
    switch (*formp) {

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

        case DW_FORM_string:
            return dieref.unit->io->readString(value().addr);

        default:
            abort();
    }
}

void
RawDIE::readValue(DWARFReader &r, Form form, Value &value, const Unit *unit)
{
    switch (form) {

    case DW_FORM_GNU_strp_alt: {
        value.addr = r.getint(unit->dwarfLen);
        break;
    }

    case DW_FORM_strp:
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

    case DW_FORM_ref_udata:
        value.addr = r.getuleb128();
        break;

    case DW_FORM_ref1:
        value.addr = r.getu8();
        break;

    case DW_FORM_ref2:
        value.addr = r.getu16();
        break;

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
        value.addr = r.getu8();
        break;

    default:
        value.addr = 0;
        abort();
        break;
    }
}

static int totalDIEs = 0;
static int maxDIEs = 0;
__attribute__((destructor))
void printDIEtotal()
{
    fprintf(stderr, "total dies: %d, max dies: %d\n", totalDIEs, maxDIEs);
}

RawDIE::~RawDIE()
{
    int i = 0;
    for (auto form : type->forms) {
        switch (form) {
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
    --totalDIEs;
}

const LineInfo *
Unit::getLines()
{
    if (lines != nullptr)
        return lines.get();

    if (dwarf->lineshdr == nullptr)
        return nullptr;

    const auto &r = root();
    if (r.tag() != DW_TAG_partial_unit && r.tag() != DW_TAG_compile_unit)
        return nullptr; // XXX: assert?

    auto attr = r.attribute(DW_AT_stmt_list);
    if (!attr.valid())
        return nullptr;

    auto stmts = off_t(attr);
    DWARFReader r2(dwarf->lineshdr, stmts);
    lines.reset(new LineInfo());
    lines->build(r2, this);
    return lines.get();
}

void
RawDIE::fixlinks(Unit *unit, DWARFReader &r, off_t offset)
{
    if (type->hasChildren) {
        firstChild = r.getOffset();
        if (nextSibling == 0) {
            // We can't work out where our next sibling is without
            // dragging in our children. Do that, and the new offset is our next sib.
            for (auto &it : DIE(unit->shared_from_this(), offset, this).children())
                (void)it;
        }
    } else {
        nextSibling = r.getOffset(); // we have no children, so next DIE is next sib
        firstChild = 0; // no children.
    }
}


RawDIE::RawDIE(Unit *unit, DWARFReader &r, size_t abbrev, off_t parent_)
    : type(unit->findAbbreviation(abbrev))
    , values(type->forms.size())
    , parent(parent_)
    , nextSibling(0)
{
    size_t i = 0;
    for (auto form : type->forms) {
        readValue(r, form, values[i], unit);
        if (int(i) == type->nextSibIdx) {
            // our offsets are relative to the section. The attribute is relative to the unit.
            nextSibling = values[i].sdata + unit->offset;
        }
        ++i;
    }
}

const Abbreviation *
Unit::findAbbreviation(size_t offset) const
{
    auto it = abbreviations.find(offset);
    return it != abbreviations.end() ? &it->second : nullptr;
}

Unit::AllEntries::iterator
Unit::decodeEntry(DWARFReader &r, off_t parent)
{
    intmax_t offset = r.getOffset();
    size_t abbrev = r.getuleb128();
    if (abbrev == 0) {
        if (parent)
            allEntries.at(parent).nextSibling = r.getOffset();
        return allEntries.end();
    }
    auto p = allEntries.emplace(std::piecewise_construct,
                    std::forward_as_tuple(offset),
                    std::forward_as_tuple(this, r, abbrev, parent));
    p.first->second.fixlinks(this, r, offset);
    return p.first;
}

void
Unit::decodeEntries(DWARFReader &r, off_t parent)
{
    while (!r.empty()) {
        if (decodeEntry(r, parent) == allEntries.end())
            return;
    }
}


string
Info::getAltImageName() const
{
    auto &section = elf->getSection(".gnu_debugaltlink", 0);
    const auto &name = section.io->readString(0);
    if (name[0] == '/')
        return name;

    // Not relative - prefix it with dirname of the image
    const auto &exedir = dirname(io->filename());
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
DWARFReader::getlength(size_t *addrLen)
{
    size_t length = getu32();
    if (length >= 0xfffffff0) {
        switch (length) {
            case 0xffffffff:
                if (addrLen != nullptr)
                    *addrLen = 8;
                return getuint(8);
            default:
                return 0;
        }
    } else {
        if (addrLen != nullptr)
            *addrLen = 4;
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

CFI::CFI(Info *info, Elf::Word addr, Reader::csptr io_, enum FIType type_)
    : dwarf(info)
    , sectionAddr(addr)
    , io(std::move(io_))
    , type(type_)
{
    DWARFReader reader(io);
    // decode in 2 passes: first for CIE, then for FDE
    off_t nextoff;
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
    for (const auto &fde : fdeList) {
        if (fde.iloc <= addr && fde.iloc + fde.irange > addr)
            return &fde;
    }
    return nullptr;
}

template<typename T> std::vector<std::pair<string, int>>
sourceFromAddrInUnits(const T &units, uintmax_t addr) {
    std::vector<std::pair<string, int>> info;
    for (const auto &unit : units) {
        auto lines = unit->getLines();
        if (lines) {
            for (auto i = lines->matrix.begin(); i != lines->matrix.end(); ++i) {
                if (i->end_sequence)
                    continue;
                auto next = i+1;
                if (i->addr <= addr && next->addr > addr)
                    info.emplace_back(i->file->name, i->line);
            }
        }
    }
    return info;
}

std::vector<std::pair<string, int>>
Info::sourceFromAddr(uintmax_t addr)
{
    std::vector<std::pair<string, int>> info;
    std::list<Unit::sptr> units;
    if (hasARanges()) {
        auto &rangelist = getARanges();
        for (auto &rs : rangelist) {
            for (auto &r : rs.ranges) {
                if (r.start <= addr && r.start + r.length > addr) {
                    units.push_back(getUnit(rs.debugInfoOffset));
                    break;
                }
            }
        }
    }
    if (units.empty())
        return sourceFromAddrInUnits(getUnits(), addr);
    else
        return sourceFromAddrInUnits(units, addr);
}

CallFrame::CallFrame()
    : cfaReg(0)
    , cfaValue{ .type = UNDEF, .u = { .arch = 0  } }
{
    cfaReg = 0;
    cfaValue.type = UNDEF;
#define REGMAP(number, field) registers[number].type = SAME;
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
    , lsdaEncoding(0)
    , isSignalHandler(false)
    , end(end_)
    , personality(0)
{
    version = r.getu8();
    augmentation = r.getstring();
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
                std::clog << "unknown augmentation '" << aug << "' in " << augmentation << std::endl;
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
    instructions = r.getOffset();
    r.setOffset(end);
}

Attribute::operator DIE() const
{
    if (!valid())
        return DIE();

    const Info *dwarf = dieref.unit->dwarf;
    off_t off;
    switch (*formp) {
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
    if (dwarf == dieref.unit->dwarf) {
        const auto otherEntry = dieref.unit->offsetToDIE(0, off);
        if (otherEntry)
            return otherEntry;
    }

    // Nope - try other units.
    return dwarf->offsetToDIE(off);
}

off_t
DIE::getParentOffset() const
{
    return raw->parent;
}

Unit::AllEntries::iterator
Unit::loadChildDIE(off_t parent, off_t dieOff)
{
    if (allEntries.find(dieOff) == allEntries.end()) {
        DWARFReader r(io, dieOff);
        return decodeEntry(r, parent);
    }
    return allEntries.end();
}

DIE
DIE::firstChild() const {
    return unit->offsetToDIE(offset, raw->firstChild);
}

DIE
DIE::nextSibling() const {
    return unit->offsetToDIE(raw->parent, raw->nextSibling);
}

Attribute
DIE::attribute(AttrName name) const
{
    auto loc = raw->type->attrName2Idx.find(name);
    if (loc != raw->type->attrName2Idx.end())
        return Attribute(*this, &raw->type->forms.at(loc->second));

    // If we have attributes of any of these types, we can look for other attributes in the referenced entry.
    static std::set<AttrName> derefs = {
        DW_AT_abstract_origin,
        DW_AT_specification
    };

    // don't dereference declarations, or any types that provide dereference aliases.
    if (name != DW_AT_declaration && derefs.find(name) == derefs.end()) {
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

ImageCache::ImageCache() : dwarfHits(0), dwarfLookups(0)
{
}

ImageCache::~ImageCache() {
    if (verbose >= 2)
        *debug << "DWARF image cache: lookups: " << dwarfLookups << ", hits=" << dwarfHits << std::endl;
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
            for (auto arg = type.firstChild(); arg; arg = arg.nextSibling()) {
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
findEntryForFunc(Elf::Addr address, const DIE &entry)
{
    switch (entry.tag()) {
        case DW_TAG_subprogram: {
            Elf::Addr start, end;
            auto low = entry.attribute(DW_AT_low_pc);
            auto high = entry.attribute(DW_AT_high_pc);
            if (low.valid() && high.valid()) {
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
                if (start <= address && end > address)
                    return entry;
            }
            // XXX: check ranges?
            break;
        }
        default:
            for (auto child = entry.firstChild(); child; child = child.nextSibling()) {
                auto descendent = findEntryForFunc(address, child);
                if (descendent)
                    return descendent;
            }
            break;
    }
   return DIE();
}

DIEIter
DIEChildren::begin() const {
    return const_iterator(parent.firstChild(), parent.getOffset());
}

DIEIter
DIEChildren::end() const {
    return const_iterator(DIE(), 0);
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
const Value &Attribute::value() const { return dieref.raw->values.at(formp - &dieref.raw->type->forms[0]); }
Tag DIE::tag() const { return raw->type->tag; }
bool DIE::hasChildren() const { return raw->type->hasChildren; }
}
