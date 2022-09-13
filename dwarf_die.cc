#include "libpstack/dwarf.h"
#include "libpstack/dwarf_reader.h"
#include "libpstack/global.h"
#include "libpstack/stringify.h"
#include "libpstack/fs.h"
#include <set>
#include <algorithm>

namespace Dwarf {

class DIE::Raw {
    Raw() = delete;
    Raw(const Raw &) = delete;
    const Abbreviation *type;
    std::vector<DIE::Attribute::Value> values;
    Elf::Off parent; // 0 implies we do not yet know the parent's offset.
    Elf::Off firstChild;
    Elf::Off nextSibling;
public:
    Raw(Unit *, DWARFReader &, size_t, Elf::Off parent);
    ~Raw();
    // Mostly, Raw DIEs are hidden from everything. DIE needs access though
    friend class DIE;
    static std::shared_ptr<Raw> decode(Unit *unit, const DIE &parent, Elf::Off offset);
};

DIE
DIE::firstChild() const
{
    return unit->offsetToDIE(*this, raw->firstChild);
}

DIE
DIE::nextSibling(const DIE &parent) const
{

    if (raw->nextSibling == 0) {
        // Need to work out what the next sibling is, and we don't have DW_AT_sibling
        // Run through all our children. decodeEntries will update the
        // parent's (our) nextSibling.
        std::shared_ptr<Raw> last = nullptr;
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
            case DW_FORM_addrx:
            case DW_FORM_addrx1:
            case DW_FORM_addrx2:
            case DW_FORM_addrx3:
            case DW_FORM_addrx4:
                start = uintmax_t(low);
                break;
            default:
                abort();
                break;
        }

        switch (high.form()) {
            case DW_FORM_addr:
            case DW_FORM_addrx:
            case DW_FORM_addrx1:
            case DW_FORM_addrx2:
            case DW_FORM_addrx3:
            case DW_FORM_addrx4:
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
    auto rangeattr = attribute(DW_AT_ranges);
    if (rangeattr.valid()) {
        auto ranges = unit->getRanges(*this, low.valid() ? uintmax_t(low) : 0);
        if (ranges) {
            // Iterate over the ranges, and see if the address lies inside.
            for (auto &range : *ranges)
                if (range.first <= addr && addr <= range.second)
                    return ContainsAddr::YES;
            return ContainsAddr::NO;
        }
    }
    return ContainsAddr::UNKNOWN;
}

DIE::Attribute
DIE::attribute(AttrName name, bool local) const
{
    struct cmp {
       bool operator()(const AttrName lhs, const Abbreviation::AttrNameEnt &rhs) const { return lhs < rhs.first; }
       bool operator()(const Abbreviation::AttrNameEnt &lhs, const AttrName rhs) const { return lhs.first < rhs; }
    };
    if (!raw->type->sorted) {
       std::sort(raw->type->attrName2Idx.begin(), raw->type->attrName2Idx.end());
       raw->type->sorted = true;
    }
    auto loc = std::lower_bound(
          raw->type->attrName2Idx.begin(),
          raw->type->attrName2Idx.end(),
          name, cmp());

    if (loc != raw->type->attrName2Idx.end() && loc->first == name)
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
            const auto &ao = DIE(attribute(alt));
            if (ao && ao.raw != raw)
                return ao.attribute(name);
        }
    }
    return Attribute();
}

std::string
DIE::name() const
{
    auto attr = attribute(DW_AT_name);
    return attr.valid() ? std::string(attr) : "";
}

DIE::Raw::Raw(Unit *unit, DWARFReader &r, size_t abbrev, Elf::Off parent_)
    : type(unit->findAbbreviation(abbrev))
    , parent(parent_)
    , firstChild(0)
    , nextSibling(0)
{
    size_t i = 0;
    values.reserve(type->forms.size());
    for (auto &form : type->forms) {
        values.emplace_back(r, form, unit);
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

DIE::Attribute::Value::Value(DWARFReader &r, const FormEntry &forment, Unit *unit)
{
    switch (forment.form) {

    case DW_FORM_GNU_strp_alt: {
        addr = r.getint(unit->dwarfLen);
        break;
    }

    case DW_FORM_strp:
    case DW_FORM_line_strp:
        addr = r.getint(unit->version <= 2 ? 4 : unit->dwarfLen);
        break;

    case DW_FORM_GNU_ref_alt:
        addr = r.getuint(unit->dwarfLen);
        break;

    case DW_FORM_addr:
        addr = r.getuint(unit->addrlen);
        break;

    case DW_FORM_data1:
        udata = r.getu8();
        break;

    case DW_FORM_data2:
        udata = r.getu16();
        break;

    case DW_FORM_data4:
        udata = r.getu32();
        break;

    case DW_FORM_data8:
        udata = r.getuint(8);
        break;

    case DW_FORM_sdata:
        sdata = r.getsleb128();
        break;

    case DW_FORM_udata:
        udata = r.getuleb128();
        break;

    // offsets in various sections...
    case DW_FORM_strx:
    case DW_FORM_loclistx:
    case DW_FORM_rnglistx:
    case DW_FORM_addrx:
    case DW_FORM_ref_udata:
        addr = r.getuleb128();
        break;

    case DW_FORM_strx1:
    case DW_FORM_addrx1:
    case DW_FORM_ref1:
        addr = r.getu8();
        break;

    case DW_FORM_strx2:
    case DW_FORM_addrx2:
    case DW_FORM_ref2:
        addr = r.getu16();
        break;

    case DW_FORM_addrx3:
    case DW_FORM_strx3:
        addr = r.getuint(3);
        break;

    case DW_FORM_strx4:
    case DW_FORM_addrx4:
    case DW_FORM_ref4:
        addr = r.getu32();
        break;

    case DW_FORM_ref_addr:
        addr = r.getuint(unit->dwarfLen);
        break;

    case DW_FORM_ref8:
        addr = r.getuint(8);
        break;

    case DW_FORM_string:
        addr = r.getOffset();
        r.getstring();
        break;

    case DW_FORM_block1:
        block = new Block();
        block->length = r.getu8();
        block->offset = r.getOffset();
        r.skip(block->length);
        break;

    case DW_FORM_block2:
        block = new Block();
        block->length = r.getu16();
        block->offset = r.getOffset();
        r.skip(block->length);
        break;

    case DW_FORM_block4:
        block = new Block();
        block->length = r.getu32();
        block->offset = r.getOffset();
        r.skip(block->length);
        break;

    case DW_FORM_exprloc:
    case DW_FORM_block:
        block = new Block();
        block->length = r.getuleb128();
        block->offset = r.getOffset();
        r.skip(block->length);
        break;

    case DW_FORM_flag:
        flag = r.getu8() != 0;
        break;

    case DW_FORM_flag_present:
        flag = true;
        break;

    case DW_FORM_sec_offset:
        addr = r.getint(unit->dwarfLen);
        break;

    case DW_FORM_ref_sig8:
        signature = r.getuint(8);
        break;

    case DW_FORM_implicit_const:
        sdata = forment.value;
        break;

    default:
        addr = 0;
        abort();
        break;
    }
}

DIE::Raw::~Raw()
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

static void walk(const DIE & die) { for (auto c : die.children()) { walk(c); } };
Elf::Off
DIE::getParentOffset() const
{
    if (raw->parent == 0 && !unit->isRoot(*this)) {
        // This DIE has a parent, but we did not know where it was when we
        // decoded it. We have to search for the parent in the tree. We could
        // limit our search a bit, but the easiest thing to do is just walk the
        // tree from the root down. (This also fixes the problem for any other
        // dies in the same unit.)
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

std::shared_ptr<DIE::Raw>
DIE::decode(Unit *unit, const DIE &parent, Elf::Off offset)
{
    DWARFReader r(unit->dwarf->debugInfo.io(), offset);
    size_t abbrev = r.getuleb128();
    if (abbrev == 0) {
        // If we get to the terminator, then we now know the parent's nextSibling:
        // update it now.
        if (parent)
            parent.raw->nextSibling = r.getOffset();
        return nullptr;
    }
    return std::make_shared<DIE::Raw>(unit, r, abbrev, parent.getOffset());
}

DIE::Children::const_iterator &DIE::Children::const_iterator::operator++() {
    currentDIE = currentDIE.nextSibling(parent);
    // if we loaded the child by a direct refrence into the middle of the
    // unit, (and hence didn't know the parent at the time), take the
    // opportunity to update its parent pointer
    if (currentDIE && parent && currentDIE.raw->parent == 0)
        currentDIE.raw->parent = parent.offset;
    return *this;
}

DIE::Children::const_iterator::const_iterator(const DIE &first, const DIE & parent_)
    : parent(parent_)
    , currentDIE(first)
{
    // As above, take the opportunity to update the current DIE's parent field
    // if it has not already been decided.
    if (currentDIE && parent && currentDIE.raw->parent == 0)
        currentDIE.raw->parent = parent.offset;
}

AttrName
DIE::Attribute::name() const
{
    size_t off = formp - &die.raw->type->forms[0];
    for (auto ent : die.raw->type->attrName2Idx) {
        if (ent.second == off)
            return ent.first;
    }
    return DW_AT_none;
}

DIE::Attribute::operator intmax_t() const
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

DIE::Attribute::operator uintmax_t() const
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

    case DW_FORM_addrx:
    case DW_FORM_addrx1:
    case DW_FORM_addrx2:
    case DW_FORM_addrx3:
    case DW_FORM_addrx4:
        return die.unit->dwarf->addrx(*die.unit, value().udata);

    case DW_FORM_rnglistx:
        return die.unit->dwarf->rnglistx(*die.unit, value().udata);
    default:
        abort();
    }
}

Ranges::Ranges(const DIE &die, uintmax_t base) {

    auto ranges = die.attribute(DW_AT_ranges);

    if (die.getUnit()->version < 5) {
        // DWARF4 units use debug_ranges
        DWARFReader reader(die.getUnit()->dwarf->debugRanges.io(), uintmax_t(ranges));
        for (;;) {
            auto start = reader.getuint(sizeof (Elf::Addr));
            auto end = reader.getuint(sizeof (Elf::Addr));
            if (start == 0 && end == 0)
                break;
            if (start == std::numeric_limits<Elf::Addr>::max())
                base = end;
            else
                emplace_back(std::make_pair(start + base, end + base));
        }
    } else {
        DWARFReader r(die.getUnit()->dwarf->debugRangelists.io(), uintmax_t(ranges));

        // const auto &elf = die.getUnit()->dwarf->elf;
        // auto &addrs = elf->getDebugSection(".debug_addr", SHT_NULL); // XXX: would be used by the "x" ops below

        uintmax_t base = 0;
        auto addrlen = die.getUnit()->addrlen;
        auto &unit = *die.getUnit();
        const auto &dwarf = *unit.dwarf;
        for (bool done = false; !done;) {
            auto entryType = DW_RLE(r.getu8());
            switch (entryType) {
                case DW_RLE_end_of_list:
                    done = true;
                    break;

                case DW_RLE_base_addressx: {
                    auto baseidx = r.getuleb128();
                    base = dwarf.addrx(unit, baseidx);
                    break;
                }

                case DW_RLE_startx_endx: {
                    /* auto startx = */ r.getuleb128();
                    /* auto endx = */ r.getuleb128();
                    abort();
                    break;
                }

                case DW_RLE_startx_length: {
                    auto start = dwarf.addrx(unit, r.getuleb128());
                    auto len = r.getuleb128();
                    emplace_back(start, start + len);
                    break;
                }

                case DW_RLE_offset_pair: {
                    auto offstart = r.getuleb128();
                    auto offend = r.getuleb128();
                    emplace_back(offstart + base, offend + base);
                    break;
                }

                case DW_RLE_base_address:
                    base = r.getuint(addrlen);
                    break;

                case DW_RLE_start_end: {
                    auto start = r.getuint(addrlen);
                    auto end = r.getuint(addrlen);
                    emplace_back(start, end);
                    break;
                }
                case DW_RLE_start_length: {
                    auto start = r.getuint(addrlen);
                    auto len = r.getuleb128();
                    emplace_back(start, start + len);
                    break;
                }
                default:
                    abort();
            }
        }
    }
}

DIE::Attribute::operator std::string() const
{
    if (!valid())
        return "";
    const Info *dwarf = die.unit->dwarf;
    assert(dwarf != nullptr);
    switch (formp->form) {

        case DW_FORM_GNU_strp_alt: {
            const auto &alt = dwarf->getAltDwarf();
            if (!alt)
                return "(alt string table unavailable)";
            auto &strs = alt->debugStrings;
            if (!strs)
                return "(alt string table unavailable)";
            return strs.io()->readString(value().addr);
        }
        case DW_FORM_strp:
            return dwarf->debugStrings.io()->readString(value().addr);

        case DW_FORM_line_strp:
            return dwarf->debugLineStrings.io()->readString(value().addr);

        case DW_FORM_string:
            return die.unit->dwarf->debugInfo.io()->readString(value().addr);

        case DW_FORM_strx1:
        case DW_FORM_strx2:
        case DW_FORM_strx3:
        case DW_FORM_strx4:
        case DW_FORM_strx:
            return dwarf->strx(*die.unit, value().addr);

        default:
            abort();
    }
}

DIE::Attribute::operator DIE() const
{
    if (!valid())
        return DIE();

    const Info *dwarf = die.unit->dwarf;
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
            off = value().addr + die.unit->offset;
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
    if (dwarf == die.unit->dwarf && die.unit->offset <= off && die.unit->end > off) {
        const auto otherEntry = die.unit->offsetToDIE(DIE(), off);
        if (otherEntry)
            return otherEntry;
    }

    // Nope - try other units.
    return dwarf->offsetToDIE(off);
}

DIE
DIE::findEntryForAddr(Elf::Addr address, Tag t, bool skipStart)
{
    switch (containsAddress(address)) {
        case ContainsAddr::NO:
            return DIE();
        case ContainsAddr::YES:
            if (!skipStart && tag() == t)
                return *this;
            /* FALLTHRU */
        case ContainsAddr::UNKNOWN:
            for (auto child : children()) {
                auto descendent = child.findEntryForAddr(address, t, false);
                if (descendent)
                    return descendent;
            }
            return DIE();
    }
    return DIE();
}

DIE::Children::const_iterator
DIE::Children::begin() const {
    return const_iterator(parent.firstChild(), parent);
}

DIE::Children::const_iterator
DIE::Children::end() const {
    return const_iterator(DIE(), parent);
}

std::pair<AttrName, DIE::Attribute>
DIE::Attributes::const_iterator::operator *() const {
    return std::make_pair(
            rawIter->first,
            Attribute(die, &die.raw->type->forms[rawIter->second]));
}

DIE::Attributes::const_iterator
DIE::Attributes::begin() const {
    return const_iterator(die, die.raw->type->attrName2Idx.begin());
}

DIE::Attributes::const_iterator
DIE::Attributes::end() const {
    return const_iterator(die, die.raw->type->attrName2Idx.end());
}

const DIE::Attribute::Value &DIE::Attribute::value() const {
    return die.raw->values.at(formp - &die.raw->type->forms[0]);
}

Tag DIE::tag() const {
    return raw->type->tag;
}

bool DIE::hasChildren() const {
    return raw->type->hasChildren;
}

std::string
DIE::typeName(const DIE &type)
{
    if (!*this)
        return "void";

    const auto &name = type.name();
    if (name != "")
        return name;
    auto base = DIE(type.attribute(DW_AT_type));
    std::string s, sep;
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

const Ranges * DIE::getRanges() const {
    auto ranges = attribute(DW_AT_ranges);
    if (!ranges.valid())
        return nullptr;
    auto lowpc = attribute(DW_AT_low_pc);
    return unit->getRanges(*this, lowpc.valid() ? uintmax_t(lowpc) : 0);
}

}
