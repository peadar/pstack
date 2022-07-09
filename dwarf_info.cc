#include "libpstack/dwarf.h"
#include "libpstack/dwarf_reader.h"
#include "libpstack/stringify.h"
#include "libpstack/fs.h"
#include "libpstack/global.h"
#include <memory>
#include <algorithm>

namespace Dwarf {

std::unique_ptr<CFI>
Info::decodeCFI(const char *name, const char *zname, FIType ftype) const {
    const Elf::Section *sec;
    auto io = elf->sectionReader(name, zname, &sec);
    if (!io)
        return std::unique_ptr<CFI>();
    try {
        return std::make_unique<CFI>(this, sec->shdr.sh_addr, io, ftype);
    }
    catch (const Exception &ex) {
        *debug << "can't decode " << name << " for " << *elf->io << ": "
            << ex.what() << "\n";
    }
    return std::unique_ptr<CFI>();
};

CFI *
Info::getEhFrame() const {
    if (!ehFrameLoaded) {
        ehFrameLoaded = true;
        ehFrame = decodeCFI(".eh_frame", nullptr, FI_EH_FRAME);
    }
    return ehFrame.get();
}

CFI *
Info::getDebugFrame() const {
    if (!debugFrameLoaded) {
        debugFrameLoaded = true;
        debugFrame = decodeCFI(".debug_frame", ".zdebug_frame", FI_DEBUG_FRAME);
    }
    return debugFrame.get();
}

Info::Info(Elf::Object::sptr obj, ImageCache &cache_)
    : elf(obj)
    , debugInfo(obj->sectionReader(".debug_info", ".zdebug_info"))
    , debugStrings(obj->sectionReader(".debug_str", ".zdebug_str"))
    , debugLineStrings(obj->sectionReader(".debug_line_str", ".zdebug_line_str"))
    , debugRanges(obj->sectionReader(".debug_ranges", ".zdebug_ranges"))
    , debugStrOffsets(obj->sectionReader(".debug_str_offsets", ".zdebug_str_offsets"))
    , imageCache(cache_)
{
}

std::vector<std::pair<std::string, int>>
Info::sourceFromAddr(uintmax_t addr) const
{
    std::vector<std::pair<std::string, int>> info;

    const auto &unit = lookupUnit(addr);
    if (unit)
        unit->sourceFromAddr(Elf::Addr(addr), info);
    return info;
}

const std::list<PubnameUnit> &
Info::pubnames() const
{
    if (pubnameUnits == nullptr) {
        auto pubnamesh {elf->sectionReader(".debug_pubnames", ".zdebug_pubnames")};
        pubnameUnits.reset( new std::list<PubnameUnit> );
        if (pubnamesh) {
            DWARFReader r(pubnamesh);
            while (!r.empty())
                pubnameUnits->emplace_back(r);
        }
    }
    return *pubnameUnits;
}

Unit::sptr
Info::getUnit(Elf::Off offset) const
{
    auto &ent = units[offset];
    if (ent == nullptr) {
        DWARFReader r(debugInfo, offset);
        ent = std::make_shared<Unit>(this, r);
        if (verbose >= 3)
            *debug << "create unit " << ent->name() << "@" << offset
                      << " in " << *debugInfo << "\n";
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
    for (Units::iterator start(this, uOffset), end; start != end; ++start, ++i) {
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
                                  << " in " << *debugInfo
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

Info::Units
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
        auto arangesh = elf->sectionReader(".debug_aranges", ".zdebug_aranges");
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
            if (lowpc.valid() && highpc.valid()) {
               uintmax_t low = uintmax_t(lowpc);
               uintmax_t high = uintmax_t(highpc);
               if (highpc.form() != DW_FORM_addr)
                  high += low;
               (*aranges)[high] = std::make_pair(high - low, u->offset);
            }
            // do we have ranges for this DIE?
            auto ranges = root.getRanges();
            if (ranges)
                for (auto r : *ranges)
                    (*aranges)[r.second] = std::make_pair(r.first, u->offset);
        }
    }

    // Try again now we've added all the unit ranges.
    it = aranges->upper_bound(addr);
    if (it != aranges->end() && it->first - it->second.first <= addr)
        return getUnit(it->second.second);
    return nullptr;
}


std::string
Info::strx(Unit &unit, size_t idx) const {
    if (!debugStrOffsets)
        throw Exception() << "no string offsets table, but have strx form";
    // Get the root die, and the string offset base.
    auto root = unit.root();
    auto base = intmax_t(root.attribute(DW_AT_str_offsets_base));
    auto len = unit.dwarfLen;
    DWARFReader r(debugStrOffsets, base + len * idx);
    return debugStrings->readString(r.getuint(len));
}

Info::~Info() = default;
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

LineInfo *
Info::linesAt(intmax_t offset, Unit &unit) const
{
    auto lines = new LineInfo();
    auto lineshdr = elf->sectionReader(".debug_line", ".zdebug_line");
    if (lineshdr) {
        DWARFReader r(lineshdr, offset);
        lines->build(r, unit);
    }
    return lines;
}

std::string
Info::getAltImageName() const
{
    auto &section = elf->getSection(".gnu_debugaltlink", SHT_NULL);
    const auto &name = section.io()->readString(0);
    if (name[0] == '/')
        return name;

    // relative - prefix it with dirname of the image
    const auto &exedir = dirname(linkResolve(debugInfo->filename()));
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


}
