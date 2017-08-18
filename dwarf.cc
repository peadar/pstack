#include <stack>
#include <libgen.h>
#include <sstream>
#include <unistd.h>
#include <elf.h>
#include <err.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sstream>
#include <iostream>

#include <libpstack/elf.h>
#include <libpstack/dwarf.h>

extern int gVerbose;

uintmax_t
DWARFReader::getuint(int len)
{
    uintmax_t rc = 0;
    int i;
    uint8_t bytes[16];
    if (len > 16)
        throw Exception() << "can't deal with ints of size " << len;
    io->readObj(off, bytes, len);
    off += len;
    uint8_t *p = bytes + len;
    for (i = 1; i <= len; i++)
        rc = rc << 8 | p[-i];
    return rc;
}

intmax_t
DWARFReader::getint(int len)
{
    intmax_t rc;
    int i;
    uint8_t bytes[16];
    if (len > 16 || len < 1)
        throw Exception() << "can't deal with ints of size " << len;
    io->readObj(off, bytes, len);
    off += len;
    uint8_t *p = bytes + len;
    rc = (p[-1] & 0x80) ? -1 : 0;
    for (i = 1; i <= len; i++)
        rc = rc << 8 | p[-i];
    return rc;
}

uint32_t
DWARFReader::getu32()
{
    unsigned char q[4];
    io->readObj(off, q, 4);
    off += sizeof q;
    return q[0] | q[1] << 8 | q[2] << 16 | uint32_t(q[3] << 24);
}

uint16_t
DWARFReader::getu16()
{
    unsigned char q[2];
    io->readObj(off, q, 2);
    off += sizeof q;
    return q[0] | q[1] << 8;
}

uint8_t
DWARFReader::getu8()
{
    unsigned char q;
    io->readObj(off, &q, 1);
    off++;
    return q;
}

int8_t
DWARFReader::gets8()
{
    int8_t q;
    io->readObj(off, &q, 1);
    off += 1;
    return q;
}

std::string
DWARFReader::getstring()
{
    std::ostringstream s;
    for (size_t len = 0;; ++len) {
        char c;
        io->readObj(off, &c);
        off += 1;
        if (c == 0)
            break;
        s << c;
        if (len > 2000)
            abort();
    }
    return s.str();
}

uintmax_t
DWARFReader::getuleb128shift(int *shift, bool &isSigned)
{
    uintmax_t result;
    unsigned char byte;
    for (result = 0, *shift = 0;;) {
        io->readObj(off++, &byte);
        result |= (uintmax_t)(byte & 0x7f) << *shift;
        *shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }
    isSigned = (byte & 0x40) != 0;
    return result;
}

uintmax_t
DWARFReader::getuleb128()
{
    int shift;
    bool isSigned;
    return getuleb128shift(&shift, isSigned);
}

intmax_t
DWARFReader::getsleb128()
{
    int shift;
    bool isSigned;
    intmax_t result = (intmax_t) getuleb128shift(&shift, isSigned);
    if (isSigned)
        result |= - ((uintmax_t)1 << shift);
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
        pubnames.push_back(DwarfPubname(r, offset));
    }
}

DwarfInfo::DwarfInfo(std::shared_ptr<ElfObject> obj)
    : info(obj->getSection(".debug_info", SHT_PROGBITS))
    , debstr(obj->getSection(".debug_str", SHT_PROGBITS))
    , pubnamesh(obj->getSection(".debug_pubnames", SHT_PROGBITS))
    , arangesh(obj->getSection(".debug_aranges", SHT_PROGBITS))
    , debug_frame(obj->getSection(".debug_frame", SHT_PROGBITS))
    , altImageLoaded(false)
    , abbrev(obj->getSection(".debug_abbrev", SHT_PROGBITS))
    , lineshdr(obj->getSection(".debug_line", SHT_PROGBITS))
    , elf(obj)
{
    // want these first: other sections refer into this.
    if (debstr) {
        debugStrings = new char[debstr->shdr->sh_size];
        debstr->io->readObj(0, debugStrings, debstr->shdr->sh_size);
    } else {
        debugStrings = 0;
    }
    auto eh_frame = obj->getSection(".eh_frame", SHT_PROGBITS);
    if (eh_frame) {
        try {
            ehFrame = make_unique<DwarfFrameInfo>(this, eh_frame, FI_EH_FRAME);
        }
        catch (const Exception &ex) {
            ehFrame = 0;
            std::clog << "can't decode .eh_frame for "
                << obj->getio()->describe() << ": " << ex.what() << "\n";
        }
    } else {
        ehFrame = 0;
    }

    if (debug_frame && ! noDebugLibs) {
        DWARFReader reader(debug_frame);
        try {
            debugFrame = make_unique<DwarfFrameInfo>(this, debug_frame, FI_DEBUG_FRAME);
        }
        catch (const Exception &ex) {
            debugFrame = 0;
            std::clog << "can't decode .debug_frame for "
                << obj->getio()->describe() << ": " << ex.what() << "\n";
        }
    } else {
        debugFrame = 0;
    }

}

std::list<DwarfPubnameUnit> &
DwarfInfo::pubnames()
{
    if (pubnamesh) {
        DWARFReader r(pubnamesh);
        while (!r.empty())
            pubnameUnits.push_back(DwarfPubnameUnit(r));
        pubnamesh = 0;
    }
    return pubnameUnits;
}

std::shared_ptr<DwarfUnit>
DwarfInfo::getUnit(off_t offset)
{
    auto unit = unitsm.find(offset);
    if (unit != unitsm.end())
        return unit->second;
    if (info == 0)
        return std::shared_ptr<DwarfUnit>();
    DWARFReader r(info, offset);
    unitsm[offset] = std::make_shared<DwarfUnit>(this, r);
    return unitsm[offset];
}

std::list<std::shared_ptr<DwarfUnit>>
DwarfInfo::getUnits()
{
    std::list<std::shared_ptr<DwarfUnit>> list;
    if (info == 0)
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
            aranges.push_back(DwarfARangeSet(r));
        arangesh = 0;
    }
    return aranges;
}

DwarfInfo::~DwarfInfo()
{
    delete[] debugStrings;
}

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
        if (start == 0 && length == 0)
            break;
        ranges.push_back(DwarfARange(start, length));
    }
}

DwarfUnit::DwarfUnit(DwarfInfo *di, DWARFReader &r)
    : dwarf(di)
    , offset(r.getOffset())
{
    length = r.getlength(&dwarfLen);
    Elf_Off nextoff = r.getOffset() + length;
    version = r.getu16();

    off_t off = r.getuint(dwarfLen);
    DWARFReader abbR(di->abbrev, off);
    r.addrLen = addrlen = r.getu8();
    uintmax_t code;
    while ((code = abbR.getuleb128()) != 0)
        abbreviations[DwarfTag(code)] = DwarfAbbreviation(abbR, code);

    DWARFReader entriesR(r, r.getOffset(), nextoff - r.getOffset());
    assert(nextoff <= r.getLimit());
    decodeEntries(entriesR, entries, nullptr);
    r.setOffset(nextoff);
}

std::string
DwarfUnit::name() const
{
    return entries.begin()->second->name();
}

DwarfAbbreviation::DwarfAbbreviation(DWARFReader &r, intmax_t code_)
    : code(code_)
{
    tag = DwarfTag(r.getuleb128());
    hasChildren = DwarfHasChildren(r.getu8());
    for (;;) {
        uintmax_t name, form;
        name = r.getuleb128();
        form = r.getuleb128();
        if (name == 0 && form == 0)
            break;
        specs.push_back(DwarfAttributeSpec(DwarfAttrName(name), DwarfForm(form)));
    }
}

static intmax_t
dwarfAttr2Int(const DwarfAttribute &attr)
{
    switch (attr.spec->form) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_sdata:
    case DW_FORM_udata:
        return attr.value.sdata;
    case DW_FORM_sec_offset:
        return attr.value.ref;
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
    basic_block = 0;
    end_sequence = 0;
    prologue_end = 0;
    epilogue_begin = 0;
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
    Elf_Off header_length = r.getuint(unit->dwarfLen);
    Elf_Off expectedEnd = header_length + r.getOffset();
    int min_insn_length = r.getu8();
    default_is_stmt = r.getu8();
    int line_base = r.gets8();
    int line_range = r.getu8();

    opcode_base = r.getu8();
    opcode_lengths.resize(opcode_base);
    for (size_t i = 1; i < opcode_base; ++i)
        opcode_lengths[i] = r.getu8();

    directories.push_back("(compiler CWD)");
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
    if (diff) {
        if (verbose)
            *debug << "warning: left " << diff
                << " bytes in line info table of " << r.io->describe() << std::endl;
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
            state.basic_block = 0;

        } else if (c == 0) {
            /* Extended opcode */
            int len = r.getuleb128();
            enum DwarfLineEOpcode code = DwarfLineEOpcode(r.getu8());
            switch (code) {
            case DW_LNE_end_sequence:
                state.end_sequence = 1;
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
            enum DwarfLineSOpcode opcode = DwarfLineSOpcode(c);
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
                state.basic_block = 0;
                break;
            case DW_LNS_set_column:
                state.column = r.getuleb128();
                break;
            case DW_LNS_negate_stmt:
                state.is_stmt = !state.is_stmt;
                break;
            case DW_LNS_set_basic_block:
                state.basic_block = 1;
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


DwarfFileEntry::DwarfFileEntry(const std::string &name_, std::string dir_,
        unsigned lastMod_, unsigned length_)
    : name(name_)
    , directory(dir_)
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

DwarfAttribute::DwarfAttribute(DWARFReader &r, const DwarfEntry *entry_, const DwarfAttributeSpec *spec_)
    : spec(spec_)
    , entry(entry_)
{
    switch (spec->form) {

    case DW_FORM_GNU_strp_alt: {
        DwarfInfo *info = entry->unit->dwarf;
        value.string = info->getAltDwarf()->debugStrings + r.getint(entry->unit->dwarfLen);
        break;
    }

    case DW_FORM_GNU_ref_alt:
        value.ref = r.getint(entry->unit->dwarfLen);
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
        value.ref = r.getuleb128();
        break;

    case DW_FORM_strp:
        value.string = entry->unit->dwarf->debugStrings + r.getint(entry->unit->dwarfLen);
        break;

    case DW_FORM_ref1:
        value.ref = r.getu8();
        break;

    case DW_FORM_ref2:
        value.ref = r.getu16();
        break;

    case DW_FORM_ref4:
        value.ref = r.getu32();
        break;

    case DW_FORM_ref_addr:
        value.ref = r.getuint(entry->unit->dwarfLen);
        break;

    case DW_FORM_ref8:
        value.ref = r.getuint(8);
        break;

    case DW_FORM_string:
        value.string = strdup(r.getstring().c_str());
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
        value.flag = r.getu8();
        break;

    case DW_FORM_flag_present:
        value.flag = 1;
        break;

    case DW_FORM_sec_offset:
        value.ref = r.getint(entry->unit->dwarfLen);
        break;

    case DW_FORM_ref_sig8:
        value.ref = r.getu8();
        break;

    default:
        abort();
        break;
    }
}

DwarfEntry *
DwarfEntry::firstChild(DwarfTag tag)
{
   for (auto &ent : children)
      if (ent.second->type->tag == tag)
         return ent.second;
   return 0;
}

DwarfEntry::DwarfEntry(DWARFReader &r, intmax_t code, DwarfUnit *unit_, intmax_t offset_, DwarfEntry *parent_)
    : parent(parent_)
    , unit(unit_)
    , type(&unit->abbreviations.find(DwarfTag(code))->second)
    , offset(offset_)
{

    for (auto spec = type->specs.begin(); spec != type->specs.end(); ++spec)
        attributes.push_back(DwarfAttribute(r, this, &(*spec)));
    switch (type->tag) {
    case DW_TAG_partial_unit:
    case DW_TAG_compile_unit: {
        auto stmtsAttr = attrForName(DW_AT_stmt_list);
        if (unit->dwarf->lineshdr && stmtsAttr) {
            size_t stmts = dwarfAttr2Int(*stmtsAttr);
            DWARFReader r2(unit->dwarf->lineshdr, stmts);
            unit_->lines.build(r2, unit);
        } else {
            if (verbose)
               *debug << "warning: no line number info found" << std::endl;
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
        intmax_t code = r.getuleb128();
        if (code == 0)
            return;
        allEntries[offset] = new DwarfEntry(r, code, this, offset, parent);
        entries[offset] = allEntries[offset];
    }
}

std::shared_ptr<DwarfInfo>
DwarfInfo::getAltDwarf()
{
    if (!altDwarf) {
        altDwarf = std::make_shared<DwarfInfo>(getAltImage());
    }
    return altDwarf;
}

std::shared_ptr<ElfObject>
DwarfInfo::getAltImage()
{
    if (!altImageLoaded) {
        altImageLoaded = true;
        auto section = elf->getSection(".gnu_debugaltlink", 0);
        char name[1024];
        assert(section->shdr->sh_size < sizeof name);
        name[section->shdr->sh_size] = 0;
        section->io->read(0, section->shdr->sh_size, name);
        char *path;
        if (name[0] != '/') {
            // Not relative - prefix it with dirname of the image
            std::ostringstream os;
            os << elf->getio()->describe();
            char absbuf[1024];
            strncpy(absbuf, os.str().c_str(), sizeof absbuf);
            dirname(absbuf);
            strncat(absbuf, "/", sizeof absbuf - 1);
            strncat(absbuf, "/", sizeof absbuf - 1);
            strncat(absbuf, name, sizeof absbuf - 1);
            path = absbuf;
        } else {
            path = name;
        }
        if (verbose)
           *debug << "io: " << elf->getio()->describe() << ", alt path: " << name << "\n";
        altImage = std::make_shared<ElfObject>(path);
    }
    return altImage;
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
        base += offset + dwarf->elf->getBase() + section->shdr->sh_offset;
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
                if (addrLen)
                    *addrLen = 8;
                return getuint(8);
            default:
                return 0;
        }
    } else {
        if (addrLen)
            *addrLen = 4;
        return length;
    }
}

Elf_Off
DwarfFrameInfo::decodeCIEFDEHdr(DWARFReader &r, Elf_Addr &id, off_t start, DwarfCIE **ciep)
{
    size_t addrLen;
    Elf_Off length = r.getlength(&addrLen);

    if (length == 0)
        return 0;

    Elf_Off idoff = r.getOffset();
    id = r.getuint(addrLen);
    if (!isCIE(id) && ciep) {
        auto ciei = cies.find(start == 0 ? idoff - id : id + start);
        *ciep = ciei != cies.end() ? &ciei->second : 0;
    }
    return idoff + length;
}

bool
DwarfFrameInfo::isCIE(Elf_Addr cieid)
{
    return (type == FI_DEBUG_FRAME && cieid == 0xffffffff) || (type == FI_EH_FRAME && cieid == 0);
}

DwarfFrameInfo::DwarfFrameInfo(DwarfInfo *info, std::shared_ptr<const ElfSection> section_, enum FIType type_)
    : dwarf(info)
    , section(section_)
    , type(type_)
{
    Elf_Addr cieid;
    DWARFReader reader(section);

    // decode in 2 passes: first for CIE, then for FDE
    off_t start = reader.getOffset();
    off_t decodeStart = type == FI_DEBUG_FRAME ? start : 0;
    off_t nextoff;
    for (; !reader.empty();  reader.setOffset(nextoff)) {
        size_t cieoff = reader.getOffset();
        nextoff = decodeCIEFDEHdr(reader, cieid, decodeStart, 0);
        if (nextoff == 0)
            break;
        if (isCIE(cieid))
            cies[cieoff] = DwarfCIE(this, reader, nextoff);
    }
    reader.setOffset(start);
    for (reader.setOffset(start); !reader.empty(); reader.setOffset(nextoff)) {
        DwarfCIE *cie;
        nextoff = decodeCIEFDEHdr(reader, cieid, decodeStart, &cie);
        if (nextoff == 0)
            break;
        if (!isCIE(cieid)) {
            if (cie == 0)
                throw Exception() << "invalid frame information in " << reader.io->describe();
            fdeList.push_back(DwarfFDE(this, reader, cie, nextoff));
        }
    }
}

const DwarfFDE *
DwarfFrameInfo::findFDE(Elf_Addr addr) const
{
    for (auto fde = fdeList.begin(); fde != fdeList.end(); ++fde)
        // XXX: addr can be just past last instruction in function
        if (fde->iloc <= addr && fde->iloc + fde->irange >= addr)
            return &(*fde);
    return 0;
}

std::vector<std::pair<const DwarfFileEntry *, int>>
DwarfInfo::sourceFromAddr(uintmax_t addr)
{
    std::vector<std::pair<const DwarfFileEntry *, int>> info;
    auto &rangelist = ranges();
    for (auto rs = rangelist.begin(); rs != rangelist.end(); ++rs) {
        for (auto r = rs->ranges.begin(); r != rs->ranges.end(); ++r) {
            if (r->start <= addr && r->start + r->length > addr) {
                const auto u = getUnit(rs->debugInfoOffset);
                for (auto i = u->lines.matrix.begin(); i != u->lines.matrix.end(); ++i) {
                    if (i->end_sequence)
                        continue;
                    auto next = i+1;
                    if (i->addr <= addr && next->addr > addr)
                        info.push_back(std::make_pair(i->file, i->line));
                }
            }
        }
    }
    return info;
}

DwarfCallFrame::DwarfCallFrame()
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
    if (addr || wantAddr) {
        DWARFReader r2(r, instructions, end - instructions);
        dframe = execInsns(r2, 0, 0);
        frame = dframe;
    }
    while (addr <= wantAddr) {
        if (r.empty())
            return frame;
        uint8_t rawOp = r.getu8();
        reg = rawOp &0x3f;
        DwarfCFAInstruction op = (DwarfCFAInstruction)(rawOp & ~0x3f);
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
            op = (DwarfCFAInstruction)(rawOp & 0x3f);
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
                frame.cfaValue.u.offset = r.getuleb128() * dataAlign;
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
    if (cie->augmentation.size() != 0 && cie->augmentation[0] == 'z') {
        size_t alen = reader.getuleb128();
        while (alen--)
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

    // Get augmentations...

#if 1 || ELF_BITS == 32
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
    if (!attr)
        return 0;

    off_t off;
    switch (attr->spec->form) {
        case DW_FORM_ref_addr:
            off = attr->value.ref;
            break;
        case DW_FORM_ref_udata:
        case DW_FORM_ref2:
        case DW_FORM_ref4:
        case DW_FORM_ref8:
            off = attr->value.ref + unit->offset;
            break;
        case DW_FORM_GNU_ref_alt:
            return 0; // XXX: deal with this.
        default:
            abort();
            break;
    }
    const auto &entry = unit->allEntries.find(off);
    if (entry != unit->allEntries.end())
        return entry->second;
    // Lets look in the parent
    for (auto u : unit->dwarf->getUnits()) {
        if (u.get() == unit)
            continue;
        const auto &entry = u->allEntries.find(off);
        if (entry != u->allEntries.end())
            return entry->second;
    }
    return 0;
}

const DwarfAttribute *
DwarfEntry::attrForName(DwarfAttrName name) const
{
    for (const auto &attr : attributes)
        if (attr.spec->name == name)
            return &attr;
    if (name != DW_AT_abstract_origin) {
        auto ao = referencedEntry(DW_AT_abstract_origin);
        if (ao != 0)
            return ao->attrForName(name);
    }
    return 0;
}
