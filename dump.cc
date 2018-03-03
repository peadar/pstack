#include <libpstack/dump.h>
#include <set>
#include <unordered_map>
#include <sys/procfs.h>
#include <cassert>
#include "libpstack/json.h"

#if ELF_BITS == 64
#define ELF_R_SYM(a) ELF64_R_SYM(a)
#define ELF_R_TYPE(a) ELF64_R_TYPE(a)
#elif ELF_BITS == 32
#define ELF_R_SYM(a) ELF32_R_SYM(a)
#define ELF_R_TYPE(a) ELF32_R_TYPE(a)
#else
#error "Non-32, non-64-bit platform?"
#endif

struct DwarfDumpCFAInsns {
    DWARFReader &r;
    DwarfDumpCFAInsns(DWARFReader &r_) : r(r_) { }
};

void
dwarfDumpCFAInsn(std::ostream &os, DWARFReader &r)
{

    Elf_Off len;
    Elf_Off off = r.getOffset();
    os
        << "{ \"offset\": " << off
        << ", \"type\": ";
    uint8_t op = r.getu8();
    switch (op >> 6) {
    case 1: os << "\"DW_CFA_advance_loc\"" << ", \"delta\":" << (op & 0x3f); break;
    case 2: os << "\"DW_CFA_offset\"" << ", \"register\": " << (op & 0x3f) << r.getuleb128(); break;
    case 3: os << "\"DW_CFA_restore\"" << ", \"register\": " << (op & 0x3f); break;

    case 0:
        switch (op & 0x3f) {
            case 0x0: os << "\"DW_CFA_nop\""; break;
            case 0x1: os << "\"DW_CFA_set_loc\""
                    << ", \"arg\":" << r.getuint(r.addrLen); break;
            case 0x2: os << "\"DW_CFA_advance_loc1\"" << ", \"arg\":" << int(r.getu8()); break;
            case 0x3: os << "\"DW_CFA_advance_loc2\"" << ", \"arg\":" <<  r.getu16(); break;
            case 0x4: os << "\"DW_CFA_advance_loc4\"" << ", \"arg\":" << r.getu32(); break;
            case 0x5: os << "\"DW_CFA_offset_extended\"" << ", \"reg\":" << r.getuleb128() << ", \"arg\":" << r.getuleb128(); break;
            case 0x6: os << "\"DW_CFA_restore_extended\"" << ", \"reg\":" << r.getuleb128(); break;
            case 0x7: os << "\"DW_CFA_undefined\"" << ", \"reg\":" << r.getuleb128(); break;
            case 0x8: os << "\"DW_CFA_same_value\"" << ", \"reg\":" << r.getuleb128(); break;
            case 0x9: os << "\"DW_CFA_register\"" << ", \"reg1\":" << r.getuleb128() << ", \"reg2\":" << r.getuleb128(); break;
            case 0xa: os << "\"DW_CFA_remember_state\""; break;
            case 0xb: os << "\"DW_CFA_restore_state\""; break;
            case 0xc: os << "\"DW_CFA_def_cfa\"" << ", \"reg\":" << r.getuleb128() << ", \"offset\":" << r.getuleb128(); break;
            case 0xd: os << "\"DW_CFA_def_cfa_register\"" << ", \"reg\":" << r.getuleb128(); break;
            case 0xe: os << "\"DW_CFA_def_cfa_offset\"" << ", \"offset\":" << r.getuleb128(); break;

            case 0xf: os << "\"DW_CFA_def_cfa_expression\"" << ", \"len\":" << (len = r.getuleb128());
                r.skip(len);
                break;

            case 0x10: os << "\"DW_CFA_expression\"" << ", \"reg\":" << r.getuleb128() << ", \"length\":" << (len = r.getuleb128());
                r.skip(len);
                break;

            case 0x12: os << "\"DW_CFA_def_cfa_sf\"" << ", \"register\": " << r.getuleb128() << ", \"offset\":" << r.getuleb128() ; break;
            case 0x13: os << "\"DW_CFA_def_cfa_offset_sf\"" << ", \"offset\":" << r.getuleb128(); break;
            case 0x16:
                os << "\"DW_CFA_val_expression\"" << ", \"length\":" << (len = r.getuleb128()) << ", \"offset\":" << r.getOffset();
                r.skip(len);
                break;

            case 0x2e: os << "\"DW_CFA_GNU_args_size\"" << ", \"offset\":" << r.getuleb128(); break;
            case 0x2d: os << "\"DW_CFA_GNU_window_size\""; break;
            case 0x2f: os << "\"DW_CFA_GNU_negative_offset_extended\""; break;
            default: throw Exception() << "unknown CFA op " << std::hex << int(op);
            break;
        }
    }
    os << " }";
}

template <typename C>
static std::ostream &
operator << (std::ostream &os, const JSON<DwarfDumpCFAInsns, C> &jinsns)
{
    auto &r = jinsns.object.r;
    os << "[ ";
    std::string sep = "";
    while (!r.empty()) {
        os << sep;
        dwarfDumpCFAInsn(os, r);
        sep = ",\n";
    }
    os << "]";
    return os;
}

std::ostream &operator << (std::ostream &os, const JSON<DwarfFileEntry> &jobj) {
    auto &fe = jobj.object;
    return JObject(os)
        .field("name", fe.name)
        .field("dir", fe.directory)
        .field("lastmod", fe.lastMod);
}

template <typename C>
std::ostream &operator << (std::ostream &os, const JSON<DwarfLineState, C> &jo) {
    auto &ls = jo.object;
    return JObject(os)
        .field("file", *ls.file)
        .field("line", ls.line)
        .field("addr", ls.addr);
}

template <typename C>
std::ostream &operator << (std::ostream &os, const JSON<DwarfLineInfo, C> &jo) {
    auto &lines = jo.object;
    return JObject(os)
        .field("default_is_stmt",  lines.default_is_stmt)
        .field("opcode_base", int(lines.opcode_base))
        .field("opcode_lengths", lines.opcode_lengths)
        .field("files", lines.files)
        .field("directories", lines.directories)
        .field("matrix", lines.matrix);
}

template <typename C>
std::ostream & operator << (std::ostream &os, const JSON<DwarfEntry, C> &jo) {
    auto &entry = jo.object;
    JObject o(os);
    o.field("type", entry.type->tag);
    o.field("offset", entry.offset);
    o.field("attributes", entry.attributes);
    if (entry.type->hasChildren)
        o.field("children", entry.children);
    return o;
}

template <typename C>
std::ostream &operator << (std::ostream &os, const JSON<DwarfAttributeSpec, C> spec) {
    return JObject(os)
        .field("name", spec.object.name)
        .field("form", spec.object.form);
}

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<DwarfAbbreviation, C> &abbr) {
    return JObject(os)
        .field("code", abbr.object.code)
        .field("has_children", abbr.object.hasChildren)
        .field("specs", abbr.object.specs);
}

std::ostream &operator << (std::ostream &os, const JSON<std::shared_ptr<DwarfUnit>> &unit) {
    return JObject(os)
        .field("length", unit.object->length)
        .field("offset",  unit.object->offset)
        .field("version",  int(unit.object->version))
        .field("addrlen",  int(unit.object->addrlen))
        .field("linenumbers", unit.object->lines)
        .field("entries", unit.object->entries);
}

std::ostream & operator << (std::ostream &os, const JSON<DwarfARange> &range) {
    return JObject(os)
        .field("start", range.object.start)
        .field("length", range.object.length);
}

std::ostream & operator << (std::ostream &os, const JSON<DwarfARangeSet> &ranges) {
    return JObject(os)
        .field("length", ranges.object.length)
        .field("version", int(ranges.object.version))
        .field("debug_info_offset", ranges.object.debugInfoOffset)
        .field("addrlen", int(ranges.object.addrlen))
        .field("descrlen",  int(ranges.object.segdesclen))
        .field("ranges", ranges.object.ranges);
}

std::ostream & operator << (std::ostream &os, const JSON<DwarfTag> &tag) {
#define DWARF_TAG(x,y) case x: return os << json(#x);
    switch (tag.object) {
#include "libpstack/dwarf/tags.h"
    default: return os << json(int(tag.object));
    }
#undef DWARF_TAG
}

std::ostream &operator << (std::ostream &os, JSON<DwarfLineEOpcode> code) {
#define DWARF_LINE_E(x,y) case x: return os << json(#x);
    switch (code.object) {
#include "libpstack/dwarf/line_e.h"
    default: return os << json(int(code.object));
    }
#undef DWARF_LINE_E
}

std::ostream &operator << (std::ostream &os, const JSON<DwarfForm> &code) {
#define DWARF_FORM(x,y) case x: return os << json(#x);
    switch (code.object) {
#include "libpstack/dwarf/forms.h"
    default: return os << json("(unknown)");
    }
#undef DWARF_FORM
}

std::ostream &
operator << (std::ostream &os, const JSON<DwarfAttrName> &code) {
#define DWARF_ATTR(x,y) case x: return os << json(#x) ;
    switch (code.object) {
#include "libpstack/dwarf/attr.h"
    default: return os << '"' << int(code.object) << '"';
    }
#undef DWARF_ATTR
}

std::ostream &
operator << (std::ostream &os, const JSON<DwarfPubname> &name) {
   return JObject(os)
      .field("offset", name.object.offset)
      .field("name", name.object.name);
}

std::ostream &
operator << (std::ostream &os, const JSON<DwarfPubnameUnit> &jo) {
    const auto &unit = jo.object;
    return JObject(os)
        .field("length", unit.length)
        .field("version", unit.version)
        .field("info offset", unit.infoOffset)
        .field("info size",  unit.infoLength)
        .field("names", unit.pubnames);
}

std::ostream &
operator << (std::ostream &os, const JSON<DwarfBlock> &b)
{
    return JObject(os)
        .field("offset", b.object.offset)
        .field("length", b.object.length);
}

struct EntryReference {
   const DwarfEntry *entry;
   EntryReference(const DwarfEntry *entry_) : entry(entry_) {}
};

std::ostream &
operator << (std::ostream &os, const JSON<EntryReference> &jer)
{
   const auto &e = jer.object.entry;
   return JObject(os)
      .field("file", stringify(*e->unit->dwarf->elf->io))
      .field("offset", e->offset)
      .field("name", e->name());
}

std::ostream &
operator << (std::ostream &os, const JSON<DwarfAttribute> &o)
{
    auto &attr = o.object;
    JObject writer(os);

    auto dwarf = attr.entry->unit->dwarf;
    auto elf = dwarf->elf;
    writer.field("form", attr.form());
    switch (attr.form()) {
    case DW_FORM_addr:
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_sec_offset:
    case DW_FORM_udata:
        writer.field("value", uintmax_t(attr));
        break;
    case DW_FORM_sdata:
        writer.field("value", intmax_t(attr));
        break;
    case DW_FORM_GNU_strp_alt:
    case DW_FORM_string:
    case DW_FORM_strp:
        writer.field("value", std::string(attr));
        break;

    case DW_FORM_ref_addr:
    case DW_FORM_ref2:
    case DW_FORM_ref4:
    case DW_FORM_ref8:
    case DW_FORM_GNU_ref_alt:
    case DW_FORM_ref_udata: {
        const auto entry = attr.entry->referencedEntry(attr.name());
        if (entry)
           writer.field("value", EntryReference(entry));
        break;

    }

    case DW_FORM_exprloc:
    case DW_FORM_block1:
    case DW_FORM_block2:
    case DW_FORM_block4:
    case DW_FORM_block:
        writer.field("value", attr.block());
        break;

    case DW_FORM_flag:
        writer.field("value", bool(attr));
        break;

    case DW_FORM_flag_present:
        writer.field("value", true);
        break;
    default:
        writer.field("value", "unknown");
    }
    return os;
}

std::ostream &
operator <<(std::ostream &os, const JSON<DwarfCIE, const DwarfFrameInfo *> &dcie)
{
    DWARFReader r(dcie.context->io, dcie.object.instructions, dcie.object.end);
    return JObject(os)
    .field("version", int(dcie.object.version))
    .field("augmentation", dcie.object.augmentation)
    .field("codeAlign", dcie.object.codeAlign)
    .field("dataAlign", dcie.object.dataAlign)
    .field("return address reg", dcie.object.rar)
    .field("instruction length", dcie.object.end - dcie.object.instructions)
    .field("LSDA encoding", int(dcie.object.lsdaEncoding))
    .field("instructions", DwarfDumpCFAInsns(r), dcie.context);
}

std::ostream &
operator << (std::ostream &os, const JSON<DwarfFDE, const DwarfFrameInfo*> &dfde)
{
    DWARFReader r(dfde.context->io, dfde.object.instructions, dfde.object.end);
    return JObject(os)
        .field("cie", intptr_t(dfde.object.cie))
        .field( "loc", dfde.object.iloc)
        .field("range", dfde.object.irange)
        .field("instructions", DwarfDumpCFAInsns(r), dfde.context);
    ;
}

struct ElfAddrStr {
   Elf_Addr addr;
   ElfAddrStr(Elf_Addr addr_) : addr(addr_) {}
};

std::ostream &
operator << (std::ostream &os, const JSON<ElfAddrStr> &addr)
{
   return os << '"' << addr.object.addr << '"';
}


std::ostream &
operator << (std::ostream &os, const JSON<DwarfFrameInfo> &info)
{
    Mapper<ElfAddrStr, decltype(info.object.cies)::mapped_type, decltype(info.object.cies)> ciesByString(info.object.cies);
    return JObject(os)
        .field("cielist", ciesByString, &info.object)
        .field("fdelist", info.object.fdeList, &info.object);
}

std::ostream &
operator << (std::ostream &os, const JSON<DwarfInfo> &jo)
{
    JObject writer(os);
    auto &dwarf = jo.object;
    writer.field("units", dwarf.getUnits())
        .field("pubnameUnits", dwarf.pubnames())
        .field("aranges", dwarf.ranges());
    if (dwarf.debugFrame)
        writer.field("debugframe", *dwarf.debugFrame);
    if (dwarf.ehFrame)
        writer.field("ehFrame", *dwarf.ehFrame);
    return writer;
}

std::ostream &operator << (std::ostream &os, const JSON<ElfNoteDesc> &jnote)
{
    const auto &note = jnote.object;
    JObject writer(os);

    writer.field("name", note.name()).field("type", note.type());

    // need to switch on type and name for notes.
    if (note.name() == "CORE") {
        auto data = note.data();
        size_t len = note.size();
        prstatus_t prstatus;
        switch (note.type()) {
            case NT_PRSTATUS:
                assert(len >= sizeof (prstatus_t));
                data->readObj(0, &prstatus);
                writer.field("prstatus", prstatus);
                break;
            case NT_AUXV:
                writer.field("auxv", ReaderArray<Elf_auxv_t>(*data));
                break;
        }
    }
    return os;
}

struct ProgramHeaderName {
   int type;
   ProgramHeaderName(int type_) : type(type_) {}
};

std::ostream &operator << (std::ostream &os, const JSON<ProgramHeaderName> &jph)
{
    auto ph = jph.object;

    static const char *segmentTypeNames[] = {
        "PT_NULL",
        "PT_LOAD",
        "PT_DYNAMIC",
        "PT_INTERP",
        "PT_NOTE",
        "PT_SHLIB",
        "PT_PHDR"
    };
    if (ph.type >= 0 && ph.type <= PT_PHDR)
        return os << json(segmentTypeNames[ph.type]);
    return os << '"' << ph.type << '"';
}

/*
 * Debug output of an ELF32 object.
 */
std::ostream &operator<< (std::ostream &os, const JSON<ElfObject> &jo)
{
    auto &obj = jo.object;
    static const char *typeNames[] = {
        "ET_NONE",
        "ET_REL",
        "ET_EXEC",
        "ET_DYN",
        "ET_CORE"
    };
    static const char *abiNames[] = {
        "SYSV/NONE",
        "HP-UX",
        "NetBSD",
        "Linux",
        "Hurd",
        "86Open",
        "Solaris",
        "Monterey",
        "Irix",
        "FreeBSD",
        "Tru64",
        "Modesto",
        "OpenBSD"
    };

    auto &ehdr = obj.getElfHeader();
    auto brand = ehdr.e_ident[EI_OSABI];

    Mapper<ProgramHeaderName, decltype(obj.programHeaders)::mapped_type, std::map<Elf_Word, ElfObject::ProgramHeaders>> mappedSegments(obj.programHeaders);
    return JObject(os)
      .field("type",  typeNames[ehdr.e_type])
      .field("entry", ehdr.e_entry)
      .field("abi", brand < sizeof abiNames / sizeof abiNames[0]? abiNames[brand] : nullptr)
      .field("sections", obj.sectionHeaders, &obj)
      .field("segments", mappedSegments, &obj)
      .field("interpreter", obj.getInterpreter())
      .field("notes", obj.notes);
    /*

    for (auto &seg :  obj.getSegments(PT_DYNAMIC)) {
        os << ", \"dynamic\": [";
        const char *sep = "";
        off_t dynoff = seg.p_offset;
        off_t edyn = dynoff + seg.p_filesz;
        for (; dynoff < edyn; dynoff += sizeof (Elf_Dyn)) {
            Elf_Dyn dyn;
            obj.io->readObj(dynoff, &dyn);
            os << sep << dyn;
            sep = ",\n";
        }
        os << "]";
        break;
    }
    */
}

std::ostream &
operator <<(std::ostream &os, const JSON<timeval> &tv)
{
    return JObject(os)
        .field("tv_sec", tv.object.tv_sec)
        .field("tv_usec", tv.object.tv_usec);
}

std::ostream &
operator <<(std::ostream &os, const JSON<Elf_auxv_t> &a)
{
    JObject writer(os);
    
    switch (a.object.a_type) {
#define AUX_TYPE(name, value) case value: writer.field("a_type", #name); break;
#include "libpstack/elf/aux.h"
    default: writer.field("a_type", a.object.a_type); break;
#undef AUX_TYPE
    }
    return writer.field("a_val", a.object.a_un.a_val);
}

std::ostream &
operator <<(std::ostream &os, const JSON<Elf_Rela> &rela)
{
   return JObject(os)
      .field("r_offset", rela.object.r_offset)
      .field("r_info-sym", ELF_R_SYM(rela.object.r_info))
      .field("r_info-type", ELF_R_TYPE(rela.object.r_info));
}

const struct sh_flag_names {
    const char *name;
    Elf_Word value;
} sh_flag_names[] = {
#define SHF_FLAG(f) { .name = #f, .value = f },
    SHF_FLAG(SHF_WRITE)
    SHF_FLAG(SHF_ALLOC)
    SHF_FLAG(SHF_EXECINSTR)
    SHF_FLAG(SHF_MERGE)
    SHF_FLAG(SHF_STRINGS)
    SHF_FLAG(SHF_INFO_LINK)
    SHF_FLAG(SHF_LINK_ORDER)
    SHF_FLAG(SHF_OS_NONCONFORMING)
    SHF_FLAG(SHF_GROUP)
    SHF_FLAG(SHF_TLS)
#ifdef SHF_COMPRESSED
    SHF_FLAG(SHF_COMPRESSED)
#endif
    SHF_FLAG(SHF_MASKOS)
    SHF_FLAG(SHF_MASKPROC)
    SHF_FLAG(SHF_ORDERED)
    SHF_FLAG((Elf_Word)SHF_EXCLUDE)
    { .name = 0, .value = 0 }
};

/*
 * Debug output of an Elf symbol.
 */
std::ostream &
operator<< (std::ostream &os, const JSON<Elf_Sym, std::tuple<const ElfObject &, const ElfSection &> *> &t)
{
    auto &s = t.object;
    auto &obj = std::get<0>(*t.context);
    auto &sec = std::get<1>(*t.context);
    static const char *bindingNames[] = {
        "STB_LOCAL",
        "STB_GLOBAL",
        "STB_WEAK",
        "unknown3",
        "unknown4",
        "unknown5",
        "unknown6",
        "unknown7",
        "unknown8",
        "unknown9",
        "unknowna",
        "unknownb",
        "unknownc",
        "STB_LOPROC",
        "STB_LOPROC + 1",
        "STB_HIPROC + 1",
    };
    static const char *typeNames[] = {
        "STT_NOTYPE",
        "STT_OBJECT",
        "STT_FUNC",
        "STT_SECTION",
        "STT_FILE",
        "STT_5",
        "STT_6",
        "STT_7",
        "STT_8",
        "STT_9",
        "STT_A",
        "STT_B",
        "STT_C",
        "STT_LOPROC",
        "STT_LOPROC + 1",
        "STT_HIPROC"
    };
    auto symStrings = obj.getSection(sec.shdr.sh_link);

    return JObject(os)
        .field("name", symStrings.io->readString(s.st_name))
        .field("value", s.st_value)
        .field("size",s.st_size)
        .field("info", (int)s.st_info)
        .field("binding", bindingNames[s.st_info >> 4])
        .field("type", typeNames[s.st_info & 0xf])
        .field("other", (int)s.st_other)
        .field("shndx", s.st_shndx);
}


std::ostream &
operator <<(std::ostream &os, const JSON<ElfSection, const ElfObject *> jsection)
{
    static const char *sectionTypeNames[] = {
        "SHT_NULL",
        "SHT_PROGBITS",
        "SHT_SYMTAB",
        "SHT_STRTAB",
        "SHT_RELA",
        "SHT_HASH",
        "SHT_DYNAMIC",
        "SHT_NOTE",
        "SHT_NOBITS",
        "SHT_REL",
        "SHT_SHLIB",
        "SHT_DYNSYM",
    };

    JObject writer(os);

    auto &o = *jsection.context;
    const auto sec = jsection.object;
    auto strs = o.getSection(o.getElfHeader().e_shstrndx);
    const Elf_Shdr &sh = sec.shdr;

    static std::set<std::string> textContent = {
        ".gnu_debugaltlink",
        ".gnu_debuglink",
        ".comment",
    };

    std::string secName = strs.io->readString(sh.sh_name);
    writer.field("size", sh.sh_size);
    writer.field("uncompressedSize", sec.io->size());
    writer.field("name", secName);
    if (sh.sh_type <= SHT_DYNSYM)
        writer.field("type", sectionTypeNames[sh.sh_type]);
    else
        writer.field("type", sh.sh_type);

    os << ", \"flags\": " << "[";

    std::string sep = "";
    for (auto i = sh_flag_names; i->name; ++i) {
        if (sh.sh_flags & i->value) {
            os << sep << "\"" << i->name << "\"";
            sep = ", ";
        }
    }
    os << "]";

    writer.field("address", sh.sh_addr);
    writer.field("offset", sh.sh_offset);
    writer.field("link", sh.sh_link);
    writer.field("info", sh.sh_info);

    switch (sh.sh_type) {
        case SHT_SYMTAB:
        case SHT_DYNSYM: {
            auto context = std::make_tuple(std::ref(o), std::ref(sec));
            writer.field("symbols", ReaderArray<Elf_Sym>(*sec.io), &context);
            break;
        }
        case SHT_RELA:
            writer.field("reloca", ReaderArray<Elf_Rela>(*sec.io));
            break;
    }

    if (textContent.find(secName) != textContent.end()) {
        char buf[1024];
        auto count = sec.io->read(0, std::min(sizeof buf - 1, size_t(sec.io->size())), buf);
        buf[count] = 0;
        os << ", \"content\": \"" << buf << "\"";
    }
    return os;
}

/*
 * Debug output of an ELF32 program segment
 */
template <typename C> std::ostream &
operator<< (std::ostream &os, const JSON<Elf_Phdr, C> &jh)
{
    auto &h = jh.object;
    JObject writer(os);

    std::set<const char *>flags;
    if (h.p_flags & PF_R)
        flags.insert("PF_R");

    if (h.p_flags & PF_W)
        flags.insert("PF_W");

    if (h.p_flags & PF_X)
        flags.insert("PF_X");

    return writer.field("offset", h.p_offset)
        .field("vaddr", h.p_vaddr)
        .field("paddr", h.p_paddr)
        .field("filesz", h.p_filesz)
        .field("memsz", h.p_memsz)
        .field("type", ProgramHeaderName(h.p_type))
        .field("flags", flags)
        .field("alignment", h.p_align);
}

struct DynTag {
    long long tag;
    DynTag(long long tag_) : tag(tag_) {}
};
std::ostream &
operator << (std::ostream &os, const JSON<DynTag> &tag)
{
#define T(a) case a: return os << json(#a);
    switch (tag.object.tag) {
    T(DT_NULL)
    T(DT_NEEDED)
    T(DT_PLTRELSZ)
    T(DT_PLTGOT)
    T(DT_HASH)
    T(DT_STRTAB)
    T(DT_SYMTAB)
    T(DT_RELA)
    T(DT_RELASZ)
    T(DT_RELAENT)
    T(DT_STRSZ)
    T(DT_SYMENT)
    T(DT_INIT)
    T(DT_FINI)
    T(DT_SONAME)
    T(DT_RPATH)
    T(DT_SYMBOLIC)
    T(DT_REL)
    T(DT_RELSZ)
    T(DT_RELENT)
    T(DT_PLTREL)
    T(DT_DEBUG)
    T(DT_TEXTREL)
    T(DT_JMPREL)
    T(DT_BIND_NOW)
    T(DT_INIT_ARRAY)
    T(DT_FINI_ARRAY)
    T(DT_INIT_ARRAYSZ)
    T(DT_FINI_ARRAYSZ)
    T(DT_RUNPATH)
    T(DT_FLAGS)
    T(DT_PREINIT_ARRAY)
    T(DT_PREINIT_ARRAYSZ)
    T(DT_NUM)
    T(DT_LOOS)
    T(DT_HIOS)
    T(DT_LOPROC)
    T(DT_HIPROC)
    T(DT_PROCNUM)
    T(DT_VALRNGLO)
    T(DT_GNU_PRELINKED)
    T(DT_GNU_CONFLICTSZ)
    T(DT_GNU_LIBLISTSZ)
    T(DT_CHECKSUM)
    T(DT_PLTPADSZ)
    T(DT_MOVEENT)
    T(DT_MOVESZ)
    T(DT_FEATURE_1)
    T(DT_POSFLAG_1)
    T(DT_SYMINSZ)
    T(DT_VALRNGHI)
    T(DT_ADDRRNGLO)
    T(DT_GNU_HASH)
    T(DT_TLSDESC_PLT)
    T(DT_TLSDESC_GOT)
    T(DT_GNU_CONFLICT)
    T(DT_GNU_LIBLIST)
    T(DT_CONFIG)
    T(DT_DEPAUDIT)
    T(DT_AUDIT)
    T(DT_PLTPAD)
    T(DT_MOVETAB)
    T(DT_SYMINFO)
    T(DT_VERSYM)
    T(DT_RELACOUNT)
    T(DT_RELCOUNT)
    T(DT_FLAGS_1)
    T(DT_VERDEF)
    T(DT_VERDEFNUM)
    T(DT_VERNEED)
    T(DT_VERNEEDNUM)
    T(DT_AUXILIARY)
    default: return os << json(int(tag.object.tag));
    }
#undef T
}

std::ostream &
operator<< (std::ostream &os, const JSON<Elf_Dyn> &d)
{
    return JObject(os)
        .field("tag", DynTag(d.object.d_tag))
        .field("word", d.object.d_un.d_val);
}

std::ostream &
operator<< (std::ostream &os, const JSON<DwarfExpressionOp> op)
{
#define DWARF_OP(name, value, args) case name: return os << json(#name);
    switch (op.object) {
#include <libpstack/dwarf/ops.h>
        default: return os << json(int(op.object));
    }
#undef DWARF_OP
}

std::ostream &
operator <<(std::ostream &os, const JSON<elf_siginfo> &prinfo)
{
    return JObject(os)
        .field("si_signo", prinfo.object.si_signo)
        .field("si_code", prinfo.object.si_code)
        .field("si_errno", prinfo.object.si_errno);
}

std::ostream &
operator <<(std::ostream &os, const JSON<prstatus_t> &jo)
{
    auto &prstat = jo.object;
    return JObject(os)
        .field("pr_info", prstat.pr_info)
        .field("pr_cursig", prstat.pr_cursig)
        .field("pr_sigpend", prstat.pr_sigpend)
        .field("pr_sighold", prstat.pr_sighold)
        .field("pr_pid", prstat.pr_pid)
        .field("pr_ppid", prstat.pr_ppid)
        .field("pr_pgrp", prstat.pr_pgrp)
        .field("pr_sid", prstat.pr_sid)
        .field("pr_utime", prstat.pr_utime)
        .field("pr_stime", prstat.pr_stime)
        .field("pr_cutime", prstat.pr_cutime)
        .field("pr_cstime", prstat.pr_cstime)
        .field("pr_reg", intptr_t(prstat.pr_reg))
        .field("pr_fpvalid", prstat.pr_fpvalid);
}

std::string
auxv_name(Elf_Word val)
{
#define AUXV(n) case n : return #n;
    switch (val) {
        AUXV(AT_NULL)
        AUXV(AT_IGNORE)
        AUXV(AT_EXECFD)
        AUXV(AT_PHDR)
        AUXV(AT_PHENT)
        AUXV(AT_PHNUM)
        AUXV(AT_PAGESZ)
        AUXV(AT_BASE)
        AUXV(AT_FLAGS)
        AUXV(AT_ENTRY)
        AUXV(AT_NOTELF)
        AUXV(AT_UID)
        AUXV(AT_EUID)
        AUXV(AT_GID)
        AUXV(AT_EGID)
        AUXV(AT_CLKTCK)
        AUXV(AT_PLATFORM)
        AUXV(AT_HWCAP)
        AUXV(AT_FPUCW)
        AUXV(AT_DCACHEBSIZE)
        AUXV(AT_ICACHEBSIZE)
        AUXV(AT_UCACHEBSIZE)
        AUXV(AT_IGNOREPPC)
        AUXV(AT_SECURE)
        AUXV(AT_BASE_PLATFORM)
#ifdef AT_RANDOM
        AUXV(AT_RANDOM)
#endif
#ifdef AT_EXECFN
        AUXV(AT_EXECFN)
#endif
        AUXV(AT_SYSINFO)
        AUXV(AT_SYSINFO_EHDR)
        AUXV(AT_L1I_CACHESHAPE)
        AUXV(AT_L1D_CACHESHAPE)
        AUXV(AT_L2_CACHESHAPE)
        AUXV(AT_L3_CACHESHAPE)
        default: return "unknown";
    }
}
#undef AUXV
