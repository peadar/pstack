#include "libpstack/dwarf.h"
#include "libpstack/stringify.h"
#include <memory>
#include <filesystem>

namespace pstack::Dwarf {

CFI *Info::getCFI(FIType type) const {
   for (auto candidate : { FI_EH_FRAME,  FI_DEBUG_FRAME } ) {
      if (candidate != type && type != FI_BEST)
         continue;
      if (cfi[ candidate ] == nullptr) {
         cfi[candidate] = std::make_unique<CFI>( this, candidate );
      }
      if (*cfi[ candidate ])
         return cfi[candidate].get();
   }
   return nullptr;
}

Info::Info(Elf::Object::sptr obj)
    : elf(std::move(obj))
    , debugInfo(elf->getDebugSection(".debug_info", SHT_NULL))
    , debugStrings(elf->getDebugSection(".debug_str", SHT_NULL))
    , debugLineStrings(elf->getDebugSection(".debug_line_str", SHT_NULL))
    , debugRanges(elf->getDebugSection(".debug_ranges", SHT_NULL))
    , debugStrOffsets(elf->getDebugSection(".debug_str_offsets", SHT_NULL))
    , debugAddr(elf->getDebugSection(".debug_addr", SHT_NULL))
    , debugRangelists(elf->getDebugSection(".debug_rnglists", SHT_NULL))
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
        pubnameUnits = std::make_unique<std::list<PubnameUnit>>();
        const Elf::Section &pubnamesh = elf->getDebugSection(".debug_pubnames", SHT_NULL);
        if (pubnamesh) {
            DWARFReader r(pubnamesh.io());
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
        DWARFReader r(debugInfo.io(), offset);
        ent = std::make_shared<Unit>(this, r);
        if (elf->context.verbose >= 3)
            *elf->context.debug << "create unit " << ent->name() << "@" << offset
                      << " in " << *debugInfo.io() << " of " << *elf->io << "\n";
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

    auto it = units.upper_bound(offset);
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
                    if (elf->context.verbose > 2)
                        *elf->context.debug << "search for DIE at " << offset
                                  << " in " << *debugInfo.io()
                                  << " started at " << uOffset
                                  << ", found at " << u->offset
                                  << " and took " << i << " iterations\n";
                    return entry;
                }
            }
            break;
        }
    }
    throw (Exception() << "DIE not found");
}

Units
Info::getUnits() const
{
    return Units{ shared_from_this() };
}

void
Info::decodeARangeSet(DWARFReader &r) const {
    Elf::Off start = r.getOffset();

    auto [ length, dwarfLen ] = r.getlength();
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
    if (segdesclen != 0) {
       // consider this an encoding error.
       if (elf->context.debug != nullptr) {
          *elf->context.debug << "warning: arangeset in " << *r.io << "has non-zero segdesclen\n";
       }
       return;
    }
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
        aranges = std::make_unique<ARanges>();
        const Elf::Section &arangesh = elf->getDebugSection(".debug_aranges", SHT_NULL);
        if (arangesh) {
            DWARFReader r(arangesh.io());
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
               auto low = uintmax_t(lowpc);
               auto high = uintmax_t(highpc);
               if (highpc.form() != DW_FORM_addr)
                  high += low;
               (*aranges)[high] = std::make_pair(high - low, u->offset);
            }
            // do we have ranges for this DIE?
            const auto &ranges = root.getRanges();
            if (ranges != nullptr)
                for (auto r : *ranges)
                    (*aranges)[r.second] = { r.first, u->offset };
        }
    }

    // Try again now we've added all the unit ranges.
    it = aranges->upper_bound(addr);
    if (it != aranges->end() && it->first - it->second.first <= addr)
        return getUnit(it->second.second);
    return nullptr;
}

Abbreviation::Abbreviation(DWARFReader &r)
    : tag(Tag(r.getuleb128()))
    , hasChildren(HasChildren(r.getu8()) == DW_CHILDREN_yes)
    , sorted(false)
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
        attrName2Idx.emplace_back(name, i);
    }
}

std::unique_ptr<LineInfo>
Info::linesAt(intmax_t offset, Unit &unit) const
{
    auto lines = std::make_unique<LineInfo>();
    const Elf::Section &lineshdr = elf->getDebugSection(".debug_line", SHT_NULL);
    if (lineshdr) {
        DWARFReader r(lineshdr.io(), offset);
        lines->build(r, unit);
    }
    return lines;
}

std::filesystem::path
Info::getAltImageName() const
{
    const Elf::Section &section = elf->getDebugSection(".gnu_debugaltlink", SHT_NULL);
    const auto &name = section.io()->readString(0);
    if (name[0] == '/')
        return name;

    // relative - prefix it with dirname of the image (note we use the image
    // from the section, not from "this", as it may have been in a separate ELF
    // image.
    const auto &exedir = elf->context.linkResolve(section.elf->io->filename()).parent_path();
    return exedir / name;
}

Info::sptr
Info::getAltDwarf() const
{
    if (!altImageLoaded) {
        altDwarf = elf->context.getDwarf(getAltImageName());
        altImageLoaded = true;
    }
    if (altDwarf == nullptr)
        throw (Exception() << "no alt-dwarf found");
    return altDwarf;
}

}
