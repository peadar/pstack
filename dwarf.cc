// vim: expandtab:ts=4:sw=4

#include "libpstack/elf.h"
#include "libpstack/dwarf.h"

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

DwarfPubname::DwarfPubname(DWARFReader &r, uint32_t offset)
    : offset(offset)
    , name(r.getstring())
{
}

DwarfPubnameUnit::DwarfPubnameUnit(DWARFReader &r)
{
    length = r.getu32();
    Elf_Off next = r.getOffset() + length;

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

static std::shared_ptr<const Reader>
sectionReader(const ElfObject &obj, const char *name)
{
    return obj.getSection(name, SHT_PROGBITS).io;
}

DwarfInfo::DwarfInfo(std::shared_ptr<ElfObject> obj, DwarfImageCache &cache_)
    : altImageLoaded(false)
    , imageCache(cache_)
    , pubnamesh(sectionReader(*obj, ".debug_pubnames"))
    , arangesh(sectionReader(*obj, ".debug_aranges"))
    , info(sectionReader(*obj, ".debug_info"))
    , elf(obj)
    , debugStrings(sectionReader(*obj, ".debug_str"))
    , abbrev(sectionReader(*obj, ".debug_abbrev"))
    , lineshdr(sectionReader(*obj, ".debug_line"))
{
    auto f = [this, &obj](const char *name, FIType ftype) {
        auto &section = obj->getSection(name, SHT_PROGBITS);
        if (!section)
            return std::unique_ptr<DwarfFrameInfo>();

        try {
            return make_unique<DwarfFrameInfo>(this, section, ftype);
        }
        catch (const Exception &ex) {
            std::clog << "can't decode " << name << " for " << *obj->io << ": " << ex.what() << "\n";
        }

        return std::unique_ptr<DwarfFrameInfo>();
    };

    ehFrame = f(".eh_frame", FI_EH_FRAME);
    debugFrame = f(".debug_frame", FI_DEBUG_FRAME);
}

std::list<DwarfPubnameUnit> &
DwarfInfo::pubnames()
{
    if (pubnamesh) {
        DWARFReader r(pubnamesh);
        while (!r.empty())
            pubnameUnits.emplace_back(r);
        pubnamesh = nullptr;
    }
    return pubnameUnits;
}

std::shared_ptr<DwarfUnit>
DwarfInfo::getUnit(off_t offset)
{
    auto unit = unitsm.find(offset);
    if (unit != unitsm.end())
        return unit->second;
    if (info == nullptr)
        return std::shared_ptr<DwarfUnit>();
    DWARFReader r(info, offset);
    unitsm[offset] = std::make_shared<DwarfUnit>(this, r);
    return unitsm[offset];
}

std::list<std::shared_ptr<DwarfUnit>>
DwarfInfo::getUnits() const
{
    std::list<std::shared_ptr<DwarfUnit>> list;
    if (info == nullptr)
        return list;
    DWARFReader r(info);

    while (!r.empty()) {
       auto off = r.getOffset();
       if (unitsm.find(off) != unitsm.end()) {
          size_t dwarfLen;
          auto length = r.getlength(&dwarfLen);
          r.setOffset(r.getOffset() + length);
       } else {
          unitsm[off] = std::make_shared<DwarfUnit>(this, r);
       }
       list.push_back(unitsm[off]);
    }
    return list;
}


std::list<DwarfARangeSet> &
DwarfInfo::ranges()
{
    if (arangesh) {
        DWARFReader r(arangesh);
        while (!r.empty())
            aranges.emplace_back(r);
        arangesh = nullptr;
    }
    return aranges;
}

DwarfInfo::~DwarfInfo() = default;

DwarfARangeSet::DwarfARangeSet(DWARFReader &r)
{
    unsigned align, tupleLen;
    Elf_Off start = r.getOffset();
    size_t dwarfLen;

    length = r.getlength(&dwarfLen);
    Elf_Off next = r.getOffset() + length;
    version = r.getu16();
    debugInfoOffset = r.getu32();
    addrlen = r.getu8();
    if (addrlen == 0)
       addrlen = 1;
    r.addrLen = addrlen;
    segdesclen = r.getu8();
    tupleLen = addrlen * 2;

    // Align on tupleLen-boundary.
    Elf_Off used = r.getOffset() - start;

    align = tupleLen - used % tupleLen;;
    r.skip(align);

    while (r.getOffset() < next) {
        uintmax_t start = r.getuint(addrlen);
        uintmax_t length = r.getuint(addrlen);
        ranges.emplace_back(start, length);
    }
}

DwarfUnit::DwarfUnit(const DwarfInfo *di, DWARFReader &r)
    : dwarf(di)
    , io(r.io)
    , offset(r.getOffset())
{
    length = r.getlength(&dwarfLen);
    Elf_Off nextoff = r.getOffset() + length;
    version = r.getu16();

    if (version <= 2) // DWARF Version 2 uses the architecture's address size.
       dwarfLen = ELF_BITS / 8;

    off_t off = r.getuint(version <= 2 ? 4 : dwarfLen);
    DWARFReader abbR(di->abbrev, off);
    r.addrLen = addrlen = r.getu8();
    uintmax_t code;
    while ((code = abbR.getuleb128()) != 0)
#ifdef NOTYET
        abbreviations.emplace( std::piecewise_construct,
                std::forward_as_tuple(DwarfTag(code)),
                std::forward_as_tuple(abbR, code));
#else
        abbreviations[DwarfTag(code)] = DwarfAbbreviation(abbR, code);
#endif
    DWARFReader entriesR(r.io, r.getOffset(), nextoff);
    assert(nextoff <= r.getLimit());
    decodeEntries(entriesR, entries, nullptr);
    r.setOffset(nextoff);
}

std::string
DwarfUnit::name() const
{
    assert(entries.begin() != entries.end());
    return (*entries.begin())->name();
}

DwarfUnit::~DwarfUnit() = default;

DwarfAbbreviation::DwarfAbbreviation(DWARFReader &r, intmax_t code_)
    : code(code_)
{
    tag = DwarfTag(r.getuleb128());
    hasChildren = DwarfHasChildren(r.getu8()) == DW_CHILDREN_yes;
    for (;;) {
        uintmax_t name, form;
        name = r.getuleb128();
        form = r.getuleb128();
        if (name == 0 && form == 0)
            break;
        specs.emplace_back(DwarfAttrName(name), DwarfForm(form));
    }
}

DwarfAttribute::operator intmax_t() const
{
    switch (spec->form) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_sdata:
    case DW_FORM_udata:
        return value.sdata;
    case DW_FORM_sec_offset:
        return value.addr;
    default:
        abort();
    }
}
DwarfAttribute::operator uintmax_t() const
{
    switch (spec->form) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
     case DW_FORM_udata:
        return value.udata;
    case DW_FORM_addr:
    case DW_FORM_sec_offset:
        return value.addr;
    default:
        abort();
    }
}

DwarfLineState::DwarfLineState(DwarfLineInfo *li)
{
    reset(li);
}

void
DwarfLineState::reset(DwarfLineInfo *li)
{
    addr = 0;
    file = &li->files[1];
    line = 1;
    column = 0;
    is_stmt = li->default_is_stmt;
    basic_block = false;
    end_sequence = false;
    prologue_end = false;
    epilogue_begin = false;
}

static void
dwarfStateAddRow(DwarfLineInfo *li, const DwarfLineState &state)
{
    li->matrix.push_back(state);
}

void
DwarfLineInfo::build(DWARFReader &r, const DwarfUnit *unit)
{
    size_t dwarfLen;
    uint32_t total_length = r.getlength(&dwarfLen);
    Elf_Off end = r.getOffset() + total_length;

    uint16_t version = r.getu16();
    (void)version;
    Elf_Off header_length = r.getuint(unit->version > 2 ? unit->dwarfLen: 4);
    Elf_Off expectedEnd = header_length + r.getOffset();
    int min_insn_length = r.getu8();
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
        std::string s = r.getstring();
        if (s == "")
            break;
        directories.push_back(s);
    }

    files.emplace_back(std::string("unknown"), std::string("unknown"), 0U, 0U); // index 0 is special
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

    DwarfLineState state(this);
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
            auto code = DwarfLineEOpcode(r.getu8());
            switch (code) {
            case DW_LNE_end_sequence:
                state.end_sequence = true;
                dwarfStateAddRow(this, state);
                state.reset(this);
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
            auto opcode = DwarfLineSOpcode(c);
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

DwarfFileEntry::DwarfFileEntry(std::string name_, std::string dir_, unsigned lastMod_, unsigned length_)
    : name(std::move(name_))
    , directory(std::move(dir_))
    , lastMod(lastMod_)
    , length(length_)
{
}

DwarfFileEntry::DwarfFileEntry(DWARFReader &r, DwarfLineInfo *info)
    : name(r.getstring())
    , directory(info->directories[r.getuleb128()])
    , lastMod(r.getuleb128())
    , length(r.getuleb128())
{
}

DwarfAttribute::operator std::string() const
{
    const DwarfInfo *dwarf = entry->unit->dwarf;
    assert(dwarf != nullptr);
    switch (spec->form) {

    case DW_FORM_GNU_strp_alt:
        return dwarf->getAltDwarf()->debugStrings->readString(value.addr);

    case DW_FORM_strp:
        return dwarf->debugStrings->readString(value.addr);

    case DW_FORM_string:
        return entry->unit->io->readString(value.addr);
    default:
        abort();
    }
}

DwarfAttribute::DwarfAttribute(DWARFReader &r, const DwarfEntry *entry_, const DwarfAttributeSpec *spec_)
    : spec(spec_)
    , value { }
    , entry(entry_)
{
    switch (spec->form) {

    case DW_FORM_GNU_strp_alt: {
        value.addr = r.getint(entry->unit->dwarfLen);
        break;
    }

    case DW_FORM_strp:
        value.addr = r.getint(entry->unit->version <= 2 ? 4 : entry->unit->dwarfLen);
        break;

    case DW_FORM_GNU_ref_alt:
        value.addr = r.getuint(entry->unit->dwarfLen);
        break;

    case DW_FORM_addr:
        value.addr = r.getuint(entry->unit->addrlen);
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
        value.addr = r.getuint(entry->unit->dwarfLen);
        break;

    case DW_FORM_ref8:
        value.addr = r.getuint(8);
        break;

    case DW_FORM_string:
        value.addr = r.getOffset();
        r.getstring();
        break;

    case DW_FORM_block1:
        value.block.length = r.getu8();
        value.block.offset = r.getOffset();
        r.skip(value.block.length);
        break;

    case DW_FORM_block2:
        value.block.length = r.getu16();
        value.block.offset = r.getOffset();
        r.skip(value.block.length);
        break;

    case DW_FORM_block4:
        value.block.length = r.getu32();
        value.block.offset = r.getOffset();
        r.skip(value.block.length);
        break;

    case DW_FORM_exprloc:
    case DW_FORM_block:
        value.block.length = r.getuleb128();
        value.block.offset = r.getOffset();
        r.skip(value.block.length);
        break;

    case DW_FORM_flag:
        value.flag = r.getu8() != 0;
        break;

    case DW_FORM_flag_present:
        value.flag = true;
        break;

    case DW_FORM_sec_offset:
        value.addr = r.getint(entry->unit->dwarfLen);
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

DwarfEntry::DwarfEntry(DWARFReader &r, DwarfTag code, DwarfUnit *unit_, intmax_t offset_, DwarfEntry *parent_)
    : parent(parent_)
    , unit(unit_)
    , type(&unit->abbreviations.find(code)->second)
    , offset(offset_)
{

    for (auto &spec : type->specs) {
#ifdef NOTYET
        attributes.emplace(std::piecewise_construct,
                std::forward_as_tuple(spec->name),
                std::forward_as_tuple(r, this, &(*spec)));
#else
        attributes[spec.name] = DwarfAttribute(r, this, &spec);
#endif
    }

    switch (type->tag) {
    case DW_TAG_partial_unit:
    case DW_TAG_compile_unit: {
        auto stmtsAttr = attrForName(DW_AT_stmt_list);
        if (unit->dwarf->lineshdr && stmtsAttr != nullptr) {
            auto stmts = off_t(*stmtsAttr);
            DWARFReader r2(unit->dwarf->lineshdr, stmts);
            unit_->lines.build(r2, unit);
        }
        break;
    }
    default: // not otherwise interested for the mo.
        break;
    }
    if (type->hasChildren)
        unit_->decodeEntries(r, children, this);
}

void
DwarfUnit::decodeEntries(DWARFReader &r, DwarfEntries &entries, DwarfEntry *parent)
{
    while (!r.empty()) {
        intmax_t offset = r.getOffset();
        intmax_t tagUleb = r.getuleb128();
        if (tagUleb == 0)
            return;
#ifdef NOTYET
        auto inserted = allEntries.emplace(std::piecewise_construct,
                    std::forward_as_tuple(offset),
                    std::forward_as_tuple(r, code, this, offset, parent));
        entries.push_back(&inserted.first->second);
#else
        auto *entry = new DwarfEntry(r, DwarfTag(tagUleb), this, offset, parent);
        allEntries[offset].reset(entry);
        entries.push_back(entry);
#endif
    }
}

static std::string
getAltImageName(const std::shared_ptr<ElfObject> &elf)
{
    auto &section = elf->getSection(".gnu_debugaltlink", 0);
    std::string name = section.io->readString(0);
    if (name[0] == '/')
        return name;

    // Not relative - prefix it with dirname of the image
    std::string exedir = dirname(stringify(*elf->io));
    return stringify(exedir, "/", name);
}

std::shared_ptr<DwarfInfo>
DwarfInfo::getAltDwarf() const
{
    if (altImageLoaded)
        return altDwarf;
    altDwarf = imageCache.getDwarf(getAltImageName(elf));
    altImageLoaded = true;
    if (altDwarf == nullptr)
        throw (Exception() << "no alt-dwarf found");
    return altDwarf;
}

intmax_t
DwarfFrameInfo::decodeAddress(DWARFReader &f, int encoding) const
{
    intmax_t base;
    Elf_Off offset = f.getOffset();
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
        base = f.getint(sizeof (Elf_Word));
        break;
    default:
        abort();
        break;
    }

    switch (encoding & 0xf0) {
    case 0:
        break;
    case DW_EH_PE_pcrel:
        base += offset + dwarf->elf->getBase() + sectionOffset;
        break;
    }
    return base;
}

Elf_Off
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

Elf_Off
DwarfFrameInfo::decodeCIEFDEHdr(DWARFReader &r, Elf_Addr &id, enum FIType type, DwarfCIE **ciep)
{
    size_t addrLen;
    Elf_Off length = r.getlength(&addrLen);

    if (length == 0)
        return 0;

    Elf_Off idoff = r.getOffset();
    id = r.getuint(addrLen);
    if (!isCIE(id)) {
        if (ciep != nullptr) {
            auto ciei = cies.find(type == FI_EH_FRAME ? idoff - id : id);
            *ciep = ciei != cies.end() ? &ciei->second : nullptr;
        }
    }
    return idoff + length;
}

bool
DwarfFrameInfo::isCIE(Elf_Addr cieid)
{
    return (type == FI_DEBUG_FRAME && cieid == 0xffffffff) || (type == FI_EH_FRAME && cieid == 0);
}

DwarfFrameInfo::DwarfFrameInfo(DwarfInfo *info, const ElfSection& section, enum FIType type_)
    : dwarf(info)
    , sectionOffset(section.shdr.sh_offset)
    , io(section.io)
    , type(type_)
{
    Elf_Addr cieid;
    DWARFReader reader(io);

    // decode in 2 passes: first for CIE, then for FDE
    off_t start = reader.getOffset();
    off_t nextoff;
    for (; !reader.empty();  reader.setOffset(nextoff)) {
        size_t cieoff = reader.getOffset();
        nextoff = decodeCIEFDEHdr(reader, cieid, type, nullptr);
        if (nextoff == 0)
            break;
        if (isCIE(cieid))
#ifdef NOTYET
            cies.emplace(std::piecewise_construct,
                    std::forward_as_tuple(cieoff),
                    std::forward_as_tuple(this, reader, nextoff));
#else
            cies[cieoff] = DwarfCIE(this, reader, nextoff);
#endif
    }
    reader.setOffset(start);
    for (reader.setOffset(start); !reader.empty(); reader.setOffset(nextoff)) {
        DwarfCIE *cie = nullptr;
        nextoff = decodeCIEFDEHdr(reader, cieid, type, &cie);
        if (nextoff == 0)
            break;
        if (!isCIE(cieid))
            fdeList.emplace_back(this, reader, cie, nextoff);
    }
}

const DwarfFDE *
DwarfFrameInfo::findFDE(Elf_Addr addr) const
{
    for (const auto &fde : fdeList)
        // XXX: addr can be just past last instruction in function
        if (fde.iloc <= addr && fde.iloc + fde.irange >= addr)
            return &fde;
    return nullptr;
}

std::vector<std::pair<const DwarfFileEntry *, int>>
DwarfInfo::sourceFromAddr(uintmax_t addr)
{
    std::vector<std::pair<const DwarfFileEntry *, int>> info;
    std::list<std::shared_ptr<DwarfUnit>> units;

    if (hasRanges()) {
        auto &rangelist = ranges();
        for (auto &rs : rangelist) {
            for (auto r = rs.ranges.begin(); r != rs.ranges.end(); ++r) {
                if (r->start <= addr && r->start + r->length > addr) {
                    units.push_back(getUnit(rs.debugInfoOffset));
                    break;
                }
            }
        }
    } else {
        units = getUnits();
    }
    for (const auto &unit : units) {
        for (auto i = unit->lines.matrix.begin(); i != unit->lines.matrix.end(); ++i) {
            if (i->end_sequence)
                continue;
            auto next = i+1;
            if (i->addr <= addr && next->addr > addr)
                info.emplace_back(i->file, i->line);
        }
    }
    return info;
}

DwarfCallFrame::DwarfCallFrame()
    : cfaReg(0)
      , cfaValue{ .type = UNDEF }
{
    cfaReg = 0;
    cfaValue.type = UNDEF;
#define REGMAP(number, field) registers[number].type = SAME;
#include <libpstack/dwarf/archreg.h>
#undef REGMAP
#ifdef CFA_RESTORE_REGNO
    registers[CFA_RESTORE_REGNO].type = ARCH;
#endif
}

DwarfCallFrame
DwarfCIE::execInsns(DWARFReader &r, uintmax_t addr, uintmax_t wantAddr)
{
    std::stack<DwarfCallFrame> stack;
    DwarfCallFrame frame;

    uintmax_t offset;
    int reg, reg2;

    // default frame for this CIE.
    DwarfCallFrame dframe;
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
        auto op = DwarfCFAInstruction(rawOp & ~0x3f);
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
            op = DwarfCFAInstruction(rawOp & 0x3f);
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
            case DW_CFA_GNU_window_size:
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

DwarfFDE::DwarfFDE(DwarfFrameInfo *fi, DWARFReader &reader, DwarfCIE *cie_, Elf_Off end_)
    : cie(cie_)
{
    iloc = fi->decodeAddress(reader, cie->addressEncoding);
    irange = fi->decodeAddress(reader, cie->addressEncoding & 0xf);
    if (!cie->augmentation.empty() && cie->augmentation[0] == 'z') {
        size_t alen = reader.getuleb128();
        while (alen-- != 0)
            augmentation.push_back(reader.getu8());
    }
    instructions = reader.getOffset();
    end = end_;
}

DwarfCIE::DwarfCIE(const DwarfFrameInfo *fi, DWARFReader &r, Elf_Off end_)
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
    Elf_Off endaugdata = r.getOffset();
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

const DwarfEntry *
DwarfEntry::referencedEntry(DwarfAttrName name) const
{
    auto attr = attrForName(name);
    return attr != nullptr ? attr->getReference() : nullptr;

}

const DwarfEntry *
DwarfAttribute::getReference() const
{

    const DwarfInfo *dwarf = entry->unit->dwarf;
    off_t off;
    switch (spec->form) {
        case DW_FORM_ref_addr:
            off = value.addr;
            break;
        case DW_FORM_ref_udata:
        case DW_FORM_ref2:
        case DW_FORM_ref4:
        case DW_FORM_ref8:
            off = value.addr + entry->unit->offset;
            break;
        case DW_FORM_GNU_ref_alt: {
            dwarf = dwarf->getAltDwarf().get();
            if (dwarf == nullptr)
                return nullptr; // XXX: deal with this.
            off = value.addr;
            break;
        }
        default:
            abort();
            break;
    }
    const auto &otherEntry = entry->unit->allEntries.find(off);

    // Try this unit first (if we're dealing with the same DwarfInfo)
    if (dwarf == entry->unit->dwarf && otherEntry != entry->unit->allEntries.end())
        return otherEntry->second.get();

    // Nope - try other units.
    for (const auto &u : dwarf->getUnits()) {
        if (u.get() == entry->unit)
            continue;
        const auto &otherEntry = u->allEntries.find(off);
        if (otherEntry != u->allEntries.end())
            return otherEntry->second.get();
    }
    return nullptr;
}

const DwarfAttribute *
DwarfEntry::attrForName(DwarfAttrName name) const
{
    auto it = attributes.find(name);
    if (it != attributes.end())
        return &it->second;

    // If we have attributes of any of these types, we can look for other attributes in the referenced entry.
    static std::set<DwarfAttrName> derefs = {
        DW_AT_abstract_origin,
        DW_AT_specification
    };

    if (derefs.find(name) == derefs.end()) {
        for (auto alt : derefs) {
            auto ao = referencedEntry(alt);
            if (ao != nullptr && ao != this)
                return ao->attrForName(name);
        }
    }

    return nullptr;
}

std::shared_ptr<DwarfInfo>
DwarfImageCache::getDwarf(const std::string &filename)
{
    return getDwarf(getImageForName(filename));
}

std::shared_ptr<DwarfInfo>
DwarfImageCache::getDwarf(std::shared_ptr<ElfObject> object)
{
    auto it = dwarfCache.find(object);
    dwarfLookups++;
    if (it != dwarfCache.end()) {
        dwarfHits++;
        return it->second;
    }

    auto dwarf = std::make_shared<DwarfInfo>(object, *this);
    dwarfCache[object] = dwarf;
    return dwarf;
}

DwarfImageCache::DwarfImageCache() : dwarfHits(0), dwarfLookups(0)
{
}

DwarfImageCache::~DwarfImageCache() {
    if (verbose >= 2)
        *debug << "DWARF image cache: lookups: " << dwarfLookups << ", hits=" << dwarfHits << std::endl;
}
