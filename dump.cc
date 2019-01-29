#include "libpstack/json.h"
#include "libpstack/dwarf.h"

#include <sys/procfs.h>

#include <cassert>
#include <iomanip>
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

struct DumpCFAInsns {
    off_t start;
    off_t end;
    explicit DumpCFAInsns(off_t start_, off_t end_)
          : start(start_)
          , end(end_)
    {}
};

std::ostream &operator <<(std::ostream &os, const JSON<Dwarf::CFAInstruction> &j)
{
    Dwarf::CFAInstruction insn = j.object;
#define DWARF_CFA_INSN(x,y) case Dwarf::x: return os << json(#x);
    switch (insn) {
#include "libpstack/dwarf/cfainsns.h"
    default: return os << json(int(insn));
    }
#undef DWARF_CFA_INSN
   return os;
}

void
dumpCFAInsn(std::ostream &os, Dwarf::DWARFReader *r)
{
    using namespace Dwarf;

    JObject jo(os);

    Elf::Off len;
    Elf::Word reg;

    CFAInstruction insn;
    uint8_t op = r->getu8();

    switch (op & 0xc0U) {
        case 0:
            insn = CFAInstruction(op);
            break;
        default:
            insn = CFAInstruction(op & 0xc0U);
            break;
    }

    jo.field("type", insn);

    switch (insn) {
        case DW_CFA_advance_loc:
            jo.field("delta", op & 0x3fU);
            break;
        case DW_CFA_offset:
            jo
                .field("register", op & 0x3fU)
                .field("offset", r->getuleb128());
            break;
        case DW_CFA_restore:
            jo.field("register", op & 0x3fU);
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
operator << (std::ostream &os, const JSON<DumpCFAInsns, C> &jinsns)
{
    Dwarf::DWARFReader r(jinsns.context->io, jinsns.object.start, jinsns.object.end);
    os << "[ ";
    std::string sep;
    while (!r.empty()) {
        os << sep;
        dumpCFAInsn(os, &r);
        sep = ",\n";
    }
    os << "]";
    return os;
}

std::ostream &operator << (std::ostream &os, const JSON<Dwarf::FileEntry> &jobj) {
    auto &fe = jobj.object;
    return JObject(os)
        .field("name", fe.name)
        .field("dir", fe.directory)
        .field("lastmod", fe.lastMod);
}

template <typename C>
std::ostream &operator << (std::ostream &os, const JSON<Dwarf::LineState, C> &jo) {
    auto &ls = jo.object;
    return JObject(os)
        .field("file", *ls.file)
        .field("line", ls.line)
        .field("addr", ls.addr);
}

template <typename C>
std::ostream &operator << (std::ostream &os, const JSON<Dwarf::LineInfo, C> &jo) {
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
std::ostream & operator << (std::ostream &os, const JSON<Dwarf::DIE, C> &jo) {
    auto &entry = jo.object;
    JObject o(os);

    o
        .field("type", entry.tag())
        .field("offset", entry.getOffset())
        .field("parent", entry.getParentOffset())
        .field("attributes", entry.attributes());

    if (entry.hasChildren())
        o.field("children", entry.children());
    return o;
}

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::Abbreviation, C> &abbr) {
    return JObject(os)
        .field("code", abbr.object.code)
        .field("has_children", abbr.object.hasChildren)
        .field("specs", abbr.object.specs);
}

std::ostream &operator << (std::ostream &os, const JSON<Dwarf::Unit::sptr> &unit) {
    JObject fmt(os);

    fmt.field("length", unit.object->length)
        .field("offset",  unit.object->offset)
        .field("version", int(unit.object->version))
        .field("addrlen", int(unit.object->addrlen))
        .field("entries", unit.object->topLevelDIEs());
    if (unit.object->getLines() != nullptr)
        fmt.field("linenumbers", *unit.object->getLines());
    return fmt;
}

std::ostream & operator << (std::ostream &os, const JSON<Dwarf::ARange> &range) {
    return JObject(os)
        .field("start", range.object.start)
        .field("length", range.object.length);
}

std::ostream & operator << (std::ostream &os, const JSON<Dwarf::ARangeSet> &ranges) {
    return JObject(os)
        .field("length", ranges.object.length)
        .field("version", int(ranges.object.version))
        .field("debug_info_offset", ranges.object.debugInfoOffset)
        .field("addrlen", int(ranges.object.addrlen))
        .field("descrlen",  int(ranges.object.segdesclen))
        .field("ranges", ranges.object.ranges);
}

std::ostream & operator << (std::ostream &os, const JSON<Dwarf::Tag> &tag) {
#define DWARF_TAG(x,y) case Dwarf::x: return os << json(#x);
    switch (tag.object) {
#include "libpstack/dwarf/tags.h"
    default: return os << json(int(tag.object));
    }
#undef DWARF_TAG
}

std::ostream &operator << (std::ostream &os, JSON<Dwarf::LineEOpcode> code) {
#define DWARF_LINE_E(x,y) case Dwarf::x: return os << json(#x);
    switch (code.object) {
#include "libpstack/dwarf/line_e.h"
    default: return os << json(int(code.object));
    }
#undef DWARF_LINE_E
}

std::ostream &operator << (std::ostream &os, const JSON<Dwarf::Form> &code) {
#define DWARF_FORM(x,y) case Dwarf::x: return os << json(#x);
    switch (code.object) {
#include "libpstack/dwarf/forms.h"
    default: return os << json("(unknown)");
    }
#undef DWARF_FORM
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::AttrName> &code) {
#define DWARF_ATTR(x,y) case Dwarf::x: return os << json(#x) ;
    switch (code.object) {
#include "libpstack/dwarf/attr.h"
    default: return os << '"' << int(code.object) << '"';
    }
#undef DWARF_ATTR
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::Pubname> &name) {
   return JObject(os)
      .field("offset", name.object.offset)
      .field("name", name.object.name);
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::PubnameUnit> &jo) {
    const auto &unit = jo.object;
    return JObject(os)
        .field("length", unit.length)
        .field("version", unit.version)
        .field("info offset", unit.infoOffset)
        .field("info size",  unit.infoLength)
        .field("names", unit.pubnames);
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::Block> &b)
{
    return JObject(os)
        .field("offset", b.object.offset)
        .field("length", b.object.length);
}

struct EntryReference {
   const Dwarf::DIE die;
   explicit EntryReference(const Dwarf::DIE &die) : die(die) {}
};

std::ostream &
operator << (std::ostream &os, const JSON<EntryReference> &jer)
{
   const auto &e = jer.object.die;
   return JObject(os)
      .field("file", stringify(*e.getUnit()->dwarf->elf->io))
      .field("name", e.name())
      .field("offset", e.getOffset())
      ;
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::Attribute> &o)
{
    using namespace Dwarf;
    auto &attr = o.object;
    JObject writer(os);

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
        const auto entry = DIE(attr);
        if (entry)
           writer.field("value", EntryReference(entry));
        break;
    }
    case DW_FORM_exprloc:
    case DW_FORM_block1:
    case DW_FORM_block2:
    case DW_FORM_block4:
    case DW_FORM_block:
        writer.field("value", Dwarf::Block(attr));
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
operator <<(std::ostream &os, const JSON<Dwarf::CIE, const Dwarf::CFI *> &dcie)
{
    return JObject(os)
    .field("version", int(dcie.object.version))
    .field("augmentation", dcie.object.augmentation)
    .field("codeAlign", dcie.object.codeAlign)
    .field("dataAlign", dcie.object.dataAlign)
    .field("return address reg", dcie.object.rar)
    .field("instruction length", dcie.object.end - dcie.object.instructions)
    .field("LSDA encoding", int(dcie.object.lsdaEncoding))
    .field("instructions", DumpCFAInsns(dcie.object.instructions, dcie.object.end), dcie.context);
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::FDE, const Dwarf::CFI*> &dfi)
{
    Dwarf::DWARFReader r(dfi.context->io, dfi->instructions, dfi->end);
    return JObject(os)
        .field("cie", dfi->cieOff)
        .field( "loc", dfi->iloc)
        .field("range", dfi->irange)
        .field("instructions", DumpCFAInsns(dfi->instructions, dfi->end), dfi.context);
}

struct AddrStr {
    Elf::Addr addr;
    explicit AddrStr(Elf::Addr addr_) : addr(addr_) {}
};

std::ostream &
operator << (std::ostream &os, const JSON<AddrStr> &addr)
{
   return os << '"' << addr.object.addr << '"';
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::CFI> &info)
{
    Mapper<AddrStr, decltype(info.object.cies)::mapped_type, decltype(info.object.cies)> ciesByString(info.object.cies);
    return JObject(os)
        .field("cielist", ciesByString, &info.object)
        .field("fdelist", info.object.fdeList, &info.object);
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::Info> &di)
{
    JObject writer(os);
    writer.field("units", di->getUnits())
        .field("pubnameUnits", di->pubnames())
        .field("aranges", di->getARanges());
    if (di->debugFrame)
        writer.field("debugframe", *di->debugFrame);
    if (di->ehFrame)
        writer.field("ehFrame", *di->ehFrame);
    return writer;
}

std::ostream &operator << (std::ostream &os, const JSON<Elf::NoteDesc> &note)
{
    JObject writer(os);
    writer
        .field("name", note->name())
        .field("type", note->type());

    // need to switch on type and name for notes.
    auto data = note->data();
    if (note->name() == "CORE") {
        prstatus_t prstatus{};
        switch (note->type()) {
            case NT_PRSTATUS:
                data->readObj(0, &prstatus);
                writer.field("prstatus", prstatus);
                break;
            case NT_AUXV:
                writer.field("auxv", ReaderArray<Elf::auxv_t>(*data));
                break;
        }
    } else if (note->name() == "GNU") {
        switch (note->type()) {
            case NT_GNU_ABI_TAG: { // https://refspecs.linuxfoundation.org/LSB_1.2.0/gLSB/noteabitag.html
                uint32_t isExecutable;
                data->readObj(0, &isExecutable);
                writer.field("abi-executable-marker", isExecutable);
                std::vector<uint32_t> kernelVersion(3);
                data->readObj(4, &kernelVersion[0], 3);
                writer.field("kernel-version", kernelVersion);
                break;
            }
            case NT_GNU_BUILD_ID: {
                std::ostringstream os;
                ReaderArray<uint8_t> content(*data);
                for (auto c : content)
                    os << std::hex << std::setw(2) << std::setfill('0') << int(c);
                writer.field("buildid", os.str());
                break;
            }
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
        strpair(PT_GNU_STACK),
        strpair(PT_GNU_RELRO)
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
std::ostream &operator<< (std::ostream &os, const JSON<Elf::Object> &elf)
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

    auto &ehdr = elf->getHeader();
    auto brand = ehdr.e_ident[EI_OSABI];

    Mapper<ProgramHeaderName, decltype(elf->programHeaders)::mapped_type, std::map<Elf::Word, Elf::Object::ProgramHeaders>> mappedSegments(elf->programHeaders);
    JObject writer(os);
    writer
        .field("type", typeNames[ehdr.e_type])
        .field("entry", ehdr.e_entry)
        .field("abi", brand < sizeof abiNames / sizeof abiNames[0]? abiNames[brand] : nullptr)
        .field("sections", elf->sectionHeaders, &elf.object)
        .field("segments", mappedSegments, &elf.object)
        .field("notes", elf->notes)
        ;

    if (elf->getInterpreter() != "")
        writer.field("interpreter", elf->getInterpreter());
    return writer;
}

std::ostream &
operator <<(std::ostream &os, const JSON<timeval> &tv)
{
    return JObject(os)
        .field("tv_sec", tv->tv_sec)
        .field("tv_usec", tv->tv_usec);
}

std::ostream &
operator <<(std::ostream &os, const JSON<Elf::auxv_t> &a)
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
operator <<(std::ostream &os, const JSON<Elf::Rela> &rela)
{
   return JObject(os)
      .field("r_offset", rela->r_offset)
      .field("r_info-sym", ELF_R_SYM(rela->r_info))
      .field("r_info-type", ELF_R_TYPE(rela->r_info));
}

const struct sh_flag_names {
    const char *name;
    Elf::Word value;
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
    SHF_FLAG((Elf::Word)SHF_EXCLUDE)
};

/*
 * Debug output of an Elf symbol.
 */
std::ostream &
operator<< (std::ostream &os,
        const JSON<Elf::Sym,
        std::tuple<const Elf::Object &, const Elf::Section &> *> &t)
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
    auto &symStrings = obj.getLinkedSection(sec);

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
operator <<(std::ostream &os, const JSON<Elf::Section, const Elf::Object *> &jsection)
{
    JObject writer(os);

    auto &o = *jsection.context;
    const auto &sec = jsection.object;
    auto &strs = o.getSection(o.getHeader().e_shstrndx);
    const Elf::Shdr &sh = sec.shdr;

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
            writer.field("symbols", ReaderArray<Elf::Sym>(*sec.io), &context);
            break;
        }
        case SHT_RELA:
            writer.field("reloca", ReaderArray<Elf::Rela>(*sec.io));
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
std::ostream &
operator<< (std::ostream &os, const JSON<Elf::Phdr, const Elf::Object *> &phdr)
{
    JObject writer(os);

    std::set<const char *>flags;
    if (phdr->p_flags & PF_R)
        flags.insert("PF_R");

    if (phdr->p_flags & PF_W)
        flags.insert("PF_W");

    if (phdr->p_flags & PF_X)
        flags.insert("PF_X");

    writer.field("offset", phdr->p_offset)
        .field("vaddr", phdr->p_vaddr)
        .field("paddr", phdr->p_paddr)
        .field("filesz", phdr->p_filesz)
        .field("memsz", phdr->p_memsz)
        .field("type", ProgramHeaderName(phdr->p_type))
        .field("flags", flags)
        .field("alignment", phdr->p_align);

    off_t strtab = 0;
    switch (phdr->p_type) {
        case PT_DYNAMIC: {
            OffsetReader dynReader(phdr.context->io, phdr->p_offset, phdr->p_filesz);
            for (const auto & i : ReaderArray<Elf::Dyn>(dynReader)) {
               if (i.d_tag == DT_STRTAB) {
                  strtab = i.d_un.d_ptr;
                  break;
               }
            }
            writer.field("dynamic", ReaderArray<Elf::Dyn>(dynReader), std::make_pair(phdr.context, strtab));
            break;
        }
    }
    return writer;
}

struct DynTag {
    Elf::Sword tag;
    explicit DynTag(Elf::Sword tag_) : tag(tag_) {}
};

std::ostream &
operator << (std::ostream &os, const JSON<DynTag> &tag)
{
#define DYN_TAG(name, value) case value: return os << json(#name);
    switch (tag->tag) {
#include "libpstack/elf/dyntag.h"
    default: return os << json(int(tag.object.tag));
    }
#undef DYN_TAG
}

std::ostream &
operator<< (std::ostream &os, const JSON<Elf::Dyn, std::pair<const Elf::Object *, off_t>> &d)
{
    JObject o(os);
    o.field("tag", DynTag(d->d_tag))
     .field("word", d->d_un.d_val);

   auto stringSeg = d.context.first->getSegmentForAddress(d.context.second);
   off_t strings = stringSeg->p_offset;
   strings += d.context.second - stringSeg->p_vaddr;

   auto printString = [&](const char *text) {
         o.field(text, d.context.first->io->readString(strings + d->d_un.d_val));
   };

   switch (d->d_tag) {
      case DT_NEEDED: printString("lib"); break;
      case DT_RPATH: printString("rpath"); break;
      case DT_SONAME: printString("soname"); break;
      case DT_RUNPATH: printString("runpath"); break;
         break;
   }
   return o;
}

std::ostream &
operator<< (std::ostream &os, const JSON<Dwarf::ExpressionOp> op)
{
#define DWARF_OP(name, value, args) case Dwarf::name: return os << json(#name);
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
