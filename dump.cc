#include "libpstack/json.h"
#include "libpstack/dwarf.h"

#include <sys/procfs.h>

#include <cassert>
#include <set>
#include <unordered_map>

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
    off_t start;
    off_t end;
    explicit DwarfDumpCFAInsns(off_t start_, off_t end_)
          : start(start_)
          , end(end_)
    {}
};

std::ostream &operator <<(std::ostream &os, const JSON<DwarfCFAInstruction> &j)
{
   DwarfCFAInstruction insn = j.object;
#define DWARF_CFA_INSN(x,y) case x: return os << json(#x);
    switch (insn) {
#include "libpstack/dwarf/cfainsns.h"
    default: return os << json(int(insn));
    }
#undef DWARF_CFA_INSN

   return os;
}

void
dwarfDumpCFAInsn(std::ostream &os, DWARFReader *r)
{

    JObject jo(os);

    Elf_Off len;
    Elf_Word reg;

    DwarfCFAInstruction insn;
    uint8_t op = r->getu8();

    switch (op & 0xc0) {
        case 0:
            insn = DwarfCFAInstruction(op);
            break;
        default:
            insn = DwarfCFAInstruction(op & 0xc0);
            break;
    }

    jo.field("type", insn);

    switch (insn) {
        case DW_CFA_advance_loc:
            jo.field("delta", op & 0x3f);
            break;
        case DW_CFA_offset:
            jo
                .field("register", op & 0x3f)
                .field("offset", r->getuleb128());
            break;
        case DW_CFA_restore:
            jo.field("register", op & 0x3f);
            break;

        case DW_CFA_set_loc:
            jo.field("arg", r->getuint(r->addrLen));
            break;

        case DW_CFA_advance_loc1:
            jo.field("arg", int(r->getu8()));
            break;

        case DW_CFA_advance_loc2:
            jo.field("arg", int(r->getu16()));
            break;

        case DW_CFA_advance_loc4:
            jo.field("arg", int(r->getu32()));
            break;

        case DW_CFA_offset_extended:
            jo
                .field("reg", r->getuleb128())
                .field("arg", r->getuleb128());
            break;

        case DW_CFA_restore_extended:
            jo.field("reg", r->getuleb128());
            break;
        case DW_CFA_undefined:
            jo.field("reg", r->getuleb128());
            break;
        case DW_CFA_same_value:
            jo.field("reg",  r->getuleb128());
            break;

        case DW_CFA_register:
            jo
                .field("reg1", r->getuleb128())
                .field("reg2", r->getuleb128());
            break;

        case DW_CFA_def_cfa:
            jo
                .field("reg", r->getuleb128())
                .field("offset", r->getuleb128());
            break;

        case DW_CFA_def_cfa_register:
            jo.field("reg", r->getuleb128());
            break;

        case DW_CFA_def_cfa_offset:
            jo.field("offset", r->getuleb128());
            break;

        case DW_CFA_def_cfa_expression:
            len = r->getuleb128();
            jo.field("len", len);
            r->skip(len);
            break;

        case DW_CFA_expression:
            jo
                .field("reg",  r->getuleb128())
                .field("length",  len = r->getuleb128());
            r->skip(len);
            break;

        case DW_CFA_def_cfa_sf:
            jo
                .field("register", r->getuleb128())
                .field("offset", r->getuleb128());
            break;

        case DW_CFA_def_cfa_offset_sf:
            jo.field("offset", r->getuleb128());
            break;

        case DW_CFA_val_expression:
	    
	    reg = r->getuleb128();
	    len = r->getuleb128();
            jo
		.field("register", reg)
		.field("length", len)
		.field("offset", r->getOffset());
            r->skip(len);
            break;
        case DW_CFA_GNU_args_size:
            jo.field("size", r->getuleb128());
            break;

        case DW_CFA_GNU_window_save:
            break;

        case DW_CFA_GNU_negative_offset_extended:
        case DW_CFA_offset_extended_sf:
            jo.field("register", r->getuleb128())
                .field("scale", r->getsleb128());
            break;

	// these instructions have no arguments, so nothing more to show
        case DW_CFA_nop:
        case DW_CFA_remember_state:
        case DW_CFA_restore_state:
            break;

        default:
            throw (Exception() << "unknown CFA op " << std::hex << int(op));
    }
}

template <typename C>
static std::ostream &
operator << (std::ostream &os, const JSON<DwarfDumpCFAInsns, C> &jinsns)
{
    DWARFReader r(jinsns.context->io, jinsns.object.start, jinsns.object.end);
    os << "[ ";
    std::string sep;
    while (!r.empty()) {
        os << sep;
        dwarfDumpCFAInsn(os, &r);
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
   explicit EntryReference(const DwarfEntry *entry_) : entry(entry_) {}
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
        if (entry != nullptr)
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
    return JObject(os)
    .field("version", int(dcie.object.version))
    .field("augmentation", dcie.object.augmentation)
    .field("codeAlign", dcie.object.codeAlign)
    .field("dataAlign", dcie.object.dataAlign)
    .field("return address reg", dcie.object.rar)
    .field("instruction length", dcie.object.end - dcie.object.instructions)
    .field("LSDA encoding", int(dcie.object.lsdaEncoding))
    .field("instructions", DwarfDumpCFAInsns(dcie.object.instructions, dcie.object.end), dcie.context);
}

std::ostream &
operator << (std::ostream &os, const JSON<DwarfFDE, const DwarfFrameInfo*> &dfi)
{
    DWARFReader r(dfi.context->io, dfi->instructions, dfi->end);
    return JObject(os)
        .field("cie", dfi->cieOff)
        .field( "loc", dfi->iloc)
        .field("range", dfi->irange)
        .field("instructions", DwarfDumpCFAInsns(dfi->instructions, dfi->end), dfi.context);
    ;
}

struct ElfAddrStr {
   Elf_Addr addr;
   explicit ElfAddrStr(Elf_Addr addr_) : addr(addr_) {}
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
operator << (std::ostream &os, const JSON<DwarfInfo> &di)
{
    JObject writer(os);
    writer.field("units", di->getUnits())
        .field("pubnameUnits", di->pubnames())
        .field("aranges", di->ranges());
    if (di->debugFrame)
        writer.field("debugframe", *di->debugFrame);
    if (di->ehFrame)
        writer.field("ehFrame", *di->ehFrame);
    return writer;
}

std::ostream &operator << (std::ostream &os, const JSON<ElfNoteDesc> &note)
{
    JObject writer(os);
    writer.field("name", note->name()).field("type", note->type());

    // need to switch on type and name for notes.
    if (note->name() == "CORE") {
        auto data = note->data();
        prstatus_t prstatus{};
        switch (note->type()) {
            case NT_PRSTATUS:
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
   explicit ProgramHeaderName(int type_) : type(type_) {}
};

std::ostream &operator << (std::ostream &os, const JSON<ProgramHeaderName> &ph)
{
    static const std::map<int, const char *> names = {
#define strpair(x) { x, #x }
        strpair(PT_NULL),
        strpair(PT_LOAD),
        strpair(PT_DYNAMIC),
        strpair(PT_INTERP),
        strpair(PT_NOTE),
        strpair(PT_SHLIB),
        strpair(PT_PHDR),
        strpair(PT_TLS),
        strpair(PT_GNU_EH_FRAME),
        strpair(PT_GNU_STACK)
#undef strpair
    };
    auto namei = names.find(ph->type);
    if (namei != names.end())
        return os << json(namei->second);
    return os << '"' << ph->type << '"';
}

/*
 * Debug output of an ELF32 object.
 */
std::ostream &operator<< (std::ostream &os, const JSON<ElfObject> &elf)
{
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

    auto &ehdr = elf->getElfHeader();
    auto brand = ehdr.e_ident[EI_OSABI];

    Mapper<ProgramHeaderName, decltype(elf->programHeaders)::mapped_type, std::map<Elf_Word, ElfObject::ProgramHeaders>> mappedSegments(elf->programHeaders);
    return JObject(os)
        .field("type", typeNames[ehdr.e_type])
        .field("entry", ehdr.e_entry)
        .field("abi", brand < sizeof abiNames / sizeof abiNames[0]? abiNames[brand] : nullptr)
        .field("sections", elf->sectionHeaders, &elf.object)
        .field("segments", mappedSegments, &elf.object)
        .field("interpreter", elf->getInterpreter())
        .field("notes", elf->notes);
/*
 * XXX: TODO post JSON fixups.
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
        .field("tv_sec", tv->tv_sec)
        .field("tv_usec", tv->tv_usec);
}

std::ostream &
operator <<(std::ostream &os, const JSON<Elf_auxv_t> &a)
{
    JObject writer(os);

    switch (a->a_type) {
#define AUX_TYPE(name, value) case value: writer.field("a_type", #name); break;
#include "libpstack/elf/aux.h"
    default: writer.field("a_type", a->a_type); break;
#undef AUX_TYPE
    }
    return writer.field("a_val", a->a_un.a_val);
}

std::ostream &
operator <<(std::ostream &os, const JSON<Elf_Rela> &rela)
{
   return JObject(os)
      .field("r_offset", rela->r_offset)
      .field("r_info-sym", ELF_R_SYM(rela->r_info))
      .field("r_info-type", ELF_R_TYPE(rela->r_info));
}

const struct sh_flag_names {
    const char *name;
    Elf_Word value;
} sh_flag_names[] = {
#define SHF_FLAG(f) { .name = #f, .value = (f) },
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
};

/*
 * Debug output of an Elf symbol.
 */
std::ostream &
operator<< (std::ostream &os, const JSON<Elf_Sym, std::tuple<const ElfObject &, const ElfSection &> *> &t)
{
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
        .field("name", symStrings.io->readString(t->st_name))
        .field("value", t->st_value)
        .field("size",t->st_size)
        .field("info", int(t->st_info))
        .field("binding", bindingNames[t->st_info >> 4])
        .field("type", typeNames[t->st_info & 0xf])
        .field("other", int(t->st_other))
        .field("shndx", t->st_shndx);
}

static const char *
sectionTypeName(intmax_t sectionType)
{
#define SECTION_TYPE(name, value) case name: return #name;
    switch (sectionType) {
#include "libpstack/elf/sectype.h"
        default:
            return "unknown";
    }
}

std::ostream &
operator <<(std::ostream &os, const JSON<ElfSection, const ElfObject *> &jsection)
{
    JObject writer(os);

    auto &o = *jsection.context;
    const auto sec = jsection.object;
    auto strs = o.getSection(o.getElfHeader().e_shstrndx);
    const Elf_Shdr &sh = sec.shdr;

    // Secions that have content that's raw text.
    static std::set<std::string> textContent = {
        ".gnu_debugaltlink",
        ".gnu_debuglink",
        ".comment",
    };

    std::set<const char *> flags;
    for (auto &flag : sh_flag_names)
        if ((sh.sh_flags & flag.value) != 0)
            flags.insert(flag.name);

    std::string secName = strs.io->readString(sh.sh_name);

    writer.field("size", sh.sh_size)
        .field("uncompressedSize", sec.io->size())
        .field("name", secName)
        .field("flags", flags)
        .field("address", sh.sh_addr)
        .field("offset", sh.sh_offset)
        .field("link", sh.sh_link)
        .field("info", sh.sh_info);

    if (sh.sh_type <= SHT_DYNSYM)
        writer.field("type", sectionTypeName(sh.sh_type));
    else
        writer.field("type", sh.sh_type);

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
        writer.field("content", buf);
    }
    return os;
}

/*
 * Debug output of an ELF32 program segment
 */
template <typename C> std::ostream &
operator<< (std::ostream &os, const JSON<Elf_Phdr, C> &phdr)
{
    JObject writer(os);

    std::set<const char *>flags;
    if (phdr->p_flags & PF_R)
        flags.insert("PF_R");

    if (phdr->p_flags & PF_W)
        flags.insert("PF_W");

    if (phdr->p_flags & PF_X)
        flags.insert("PF_X");

    return writer.field("offset", phdr->p_offset)
        .field("vaddr", phdr->p_vaddr)
        .field("paddr", phdr->p_paddr)
        .field("filesz", phdr->p_filesz)
        .field("memsz", phdr->p_memsz)
        .field("type", ProgramHeaderName(phdr->p_type))
        .field("flags", flags)
        .field("alignment", phdr->p_align);
}

struct DynTag {
    Elf_Sword tag;
    explicit DynTag(Elf_Sword tag_) : tag(tag_) {}
};

std::ostream &
operator << (std::ostream &os, const JSON<DynTag> &tag)
{
#define DYN_TAG(name, value) case name: return os << json(#name);
    switch (tag->tag) {
#include "libpstack/elf/dyntag.h"
    default: return os << json(int(tag.object.tag));
    }
#undef DYN_TAG
}

std::ostream &
operator<< (std::ostream &os, const JSON<Elf_Dyn> &d)
{
    return JObject(os)
        .field("tag", DynTag(d->d_tag))
        .field("word", d->d_un.d_val);
}

std::ostream &
operator<< (std::ostream &os, const JSON<DwarfExpressionOp> op)
{
#define DWARF_OP(name, value, args) case name: return os << json(#name);
    switch (op.object) {
#include "libpstack/dwarf/ops.h"
        default: return os << json(int(op.object));
    }
#undef DWARF_OP
}

std::ostream &
operator <<(std::ostream &os, const JSON<elf_siginfo> &prinfo)
{
    return JObject(os)
        .field("si_signo", prinfo->si_signo)
        .field("si_code", prinfo->si_code)
        .field("si_errno", prinfo->si_errno);
}

std::ostream &
operator <<(std::ostream &os, const JSON<prstatus_t> &prstatus)
{
    return JObject(os)
        .field("pr_info", prstatus->pr_info)
        .field("pr_cursig", prstatus->pr_cursig)
        .field("pr_sigpend", prstatus->pr_sigpend)
        .field("pr_sighold", prstatus->pr_sighold)
        .field("pr_pid", prstatus->pr_pid)
        .field("pr_ppid", prstatus->pr_ppid)
        .field("pr_pgrp", prstatus->pr_pgrp)
        .field("pr_sid", prstatus->pr_sid)
        .field("pr_utime", prstatus->pr_utime)
        .field("pr_stime", prstatus->pr_stime)
        .field("pr_cutime", prstatus->pr_cutime)
        .field("pr_cstime", prstatus->pr_cstime)
        .field("pr_reg", intptr_t(prstatus->pr_reg))
        .field("pr_fpvalid", prstatus->pr_fpvalid);
}
