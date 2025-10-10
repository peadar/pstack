#include "libpstack/json.h"
#include "libpstack/dwarf.h"
#include <sys/procfs.h>
#include <iomanip>
#include <set>
#include <ranges>
#include <string.h>

#if ELF_BITS == 64
#define ELF_R_SYM(a) ELF64_R_SYM(a)
#define ELF_R_TYPE(a) ELF64_R_TYPE(a)
#elif ELF_BITS == 32
#define ELF_R_SYM(a) ELF32_R_SYM(a)
#define ELF_R_TYPE(a) ELF32_R_TYPE(a)
#else
#error "Non-32, non-64-bit platform?"
#endif

namespace pstack {
struct DumpCFAInsns {
    Elf::Off start;
    Elf::Off end;
    explicit DumpCFAInsns(Elf::Off start_, Elf::Off end_)
          : start(start_)
          , end(end_)
    {}
};

std::string
to_string(Dwarf::AttrName code) {
    switch (code) {
#define DWARF_ATTR(x,y) case Dwarf::x: return #x;
#include "libpstack/dwarf/attr.h"
#undef DWARF_ATTR
    default: return "unknown";
    }
}

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

        case DW_CFA_offset_extended: {
            auto reg = r->getuleb128();
            auto arg = r->getuleb128();
            jo
                .field("reg", reg)
                .field("arg", arg);
            break;
        }

        case DW_CFA_restore_extended:
            jo.field("reg", r->getuleb128());
            break;
        case DW_CFA_undefined:
            jo.field("reg", r->getuleb128());
            break;
        case DW_CFA_same_value:
            jo.field("reg",  r->getuleb128());
            break;

        case DW_CFA_register: {
            auto reg1 = r->getuleb128();
            auto reg2 = r->getuleb128();
            jo
                .field("reg1", reg1)
                .field("reg2", reg2);
            break;
        }

        case DW_CFA_def_cfa: {
            auto reg = r->getuleb128();
            auto offset = r->getuleb128();

            jo
                .field("reg", reg)
                .field("offset", offset);
            break;
        }

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

        case DW_CFA_expression: {
            auto reg = r->getuleb128();
            auto len = r->getuleb128();
            jo
                .field("reg", reg)
                .field("length", len);
            r->skip(len);
            break;
        }

        case DW_CFA_def_cfa_sf: {
            auto reg = r->getuleb128();
            auto off = r->getuleb128();
            jo
                .field("register", reg)
                .field("offset", off);
            break;
        }

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

        case DW_CFA_GNU_negative_offset_extended:
        case DW_CFA_offset_extended_sf: {
            auto reg = r->getuleb128();
            auto scale = r->getsleb128();
            jo.field("register", reg)
                .field("scale", scale);
            break;
        }

        // these instructions have no arguments, so nothing more to show
        case DW_CFA_nop:
        case DW_CFA_remember_state:
        case DW_CFA_restore_state:
            break;

#ifndef __aarch64__
        case DW_CFA_GNU_window_save:
            break;
#else
	case DW_CFA_AARCH64_negate_ra_state:
            break;
#endif

        default:
            throw (Exception() << "unknown CFA op " << std::hex << int(op)) << std::dec;
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
        .field("dir", fe.dirindex)
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

std::ostream & operator << (std::ostream &os, const JSON<Dwarf::DIE> &jo) {
    auto &entry = jo.object;
    JObject o(os);


    const auto &attrs = entry.attributes();
    auto mappedattrs = std::views::transform(attrs, [](const auto &kv) {
          return std::make_pair(to_string(kv.first), kv.second);
          });

    o
        .field("name", entry.name())
        .field("type", entry.tag())
        .field("cuOffset", entry.getOffset() - entry.getUnit()->offset)
        .field("offset", entry.getOffset())
        .field("parent", entry.getParentOffset())
        .field("attributes", mappedattrs);

    if (entry.hasChildren())
        o.field("children", entry.children());
    return o;
}

std::ostream & operator << (std::ostream &os, const Dwarf::DIE &die) {
   return os << json(die);
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
        .field("id", unit.object->id)
        .field("unitType", unit.object->unitType)
        .field("dietree", unit.object->root());
    if (unit.object->getLines() != nullptr)
        fmt.field("linenumbers", *unit.object->getLines());

    auto macros = unit.object->getMacros();
    if (macros)
        fmt.field("macros", *macros);
    unit.object->purge();
    return fmt;
}

std::ostream & operator << (std::ostream &os, const JSON<Dwarf::Tag> &tag) {
#define DWARF_TAG(x,y) case Dwarf::x: return os << json(#x);
    switch (tag.object) {
#include "libpstack/dwarf/tags.h"
    default: return os << json(int(tag.object));
    }
#undef DWARF_TAG
}

std::ostream & operator << (std::ostream &os, const JSON<Dwarf::UnitType> &ut) {
#define DWARF_UNIT_TYPE(x,y) case Dwarf::x: return os << json(#x);
    switch (ut.object) {
#include "libpstack/dwarf/unittype.h"
    default: return os << json(int(ut.object));
    }
#undef DWARF_UNIT_TYPE
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

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::Encoding> &b)
{
#define DWARF_ATE(enc, val) case Dwarf::enc: os << json(#enc) ; break;

    switch (b.object) {
#include "libpstack/dwarf/encodings.h"
        default: os << int(b.object); break;
    }
    return os;
}


std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::DIE::Attribute> &o)
{
    using namespace Dwarf;
    auto &attr = o.object;
    JObject writer(os);

    writer.field("form", attr.form());

    switch (attr.name()) {
        case DW_AT_encoding:
            writer.field("value", Encoding(uintmax_t(attr)));
            break;
        default:
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
                case DW_FORM_implicit_const:
                    writer.field("value", intmax_t(attr));
                    break;

                case DW_FORM_GNU_strp_alt:
                case DW_FORM_string:
                case DW_FORM_strp:
                case DW_FORM_line_strp:
                case DW_FORM_strx:
                case DW_FORM_strx1:
                case DW_FORM_strx2:
                case DW_FORM_strx3:
                case DW_FORM_strx4:
                    writer.field("value", std::string(attr));
                    break;

                case DW_FORM_ref_addr:
                case DW_FORM_ref2:
                case DW_FORM_ref4:
                case DW_FORM_ref8:
                case DW_FORM_GNU_ref_alt:
                case DW_FORM_ref_udata: {
                    writer.field("value", attr.value().addr);
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
            break;
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
    .field("instruction length", dcie.object.end - dcie.object.initial_instructions)
    .field("LSDA encoding", int(dcie.object.lsdaEncoding))
    .field("instructions", DumpCFAInsns(dcie.object.initial_instructions, dcie.object.end), dcie.context)
    ;
}

std::ostream &
operator << (std::ostream &os, const JSON<std::unique_ptr<Dwarf::FDE>, const Dwarf::CFI*> &dfi)
{
    return JObject(os)
        .field( "loc", dfi.object->iloc)
        .field("range", dfi.object->irange)
        .field("instructions", DumpCFAInsns(dfi.object->instructions, dfi.object->end), dfi.context);
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::CFI> &info)
{
    const Dwarf::CFI::CIEs &cies = info.object.getCIEs();
    auto converted = std::views::transform( cies, [](const auto &stringcie) {
          return std::make_pair(std::to_string(stringcie.first), stringcie.second);
          });

    return JObject(os)
        .field("cielist", converted, &info.object)
        .field("fdelist", info.object.getFDEs(), &info.object)
        ;
   return os;
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::Macros> &mi)
{
    return JObject(os)
        .field("version", mi.object.version)
        .field("debug_line_offset", mi.object.debug_line_offset)
        .field("opcodes", mi.object.opcodes);
    // XXX: use a visitor to generate details?
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::Info> &di)
{
    JObject writer(os);
    writer.field("units", di.object.getUnits())
        .field("pubnameUnits", di.object.pubnames())
        ; // XXX .field("aranges", di->getARanges());

    auto debugFrame = di.object.getCFI( Dwarf::FI_DEBUG_FRAME );
    if (debugFrame)
        writer.field("debugframe", *debugFrame);
    auto ehFrame = di.object.getCFI( Dwarf::FI_EH_FRAME );
    if (ehFrame)
        writer.field("ehFrame", *ehFrame);
    return writer;
}

std::ostream &
operator << (std::ostream &os, const JSON<Elf::NoteDesc> &note)
{
    JObject writer(os);
    writer
        .field("name", note.object.name())
        .field("type", note.object.type());

    // need to switch on type and name for notes.
    auto data = note.object.data();
    if (note.object.name() == "CORE") {
        switch (note.object.type()) {
            case NT_PRSTATUS:
                writer.field("prstatus", data->readObj<prstatus_t>(0));
                break;
            case NT_PRPSINFO:
                writer.field("prpsinfo", data->readObj<prpsinfo_t>(0) );
                break;

            case NT_AUXV:
                writer.field("auxv", ReaderArray<Elf::auxv_t>(*data));
                break;
        }
    } else if (note.object.name() == "GNU") {
        switch (note.object.type()) {
            case NT_GNU_ABI_TAG: {
                // https://refspecs.linuxfoundation.org/LSB_1.2.0/gLSB/noteabitag.html
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
                    os << std::hex << std::setw(2) << std::setfill('0') << int(c) << std::dec;
                writer.field("buildid", os.str());
                break;
            }
        }
    }
    return os;
}

std::string_view programHeaderName( int ph ) {
    switch( ph ) {
#define strpair(x) case x: return #x
        strpair(PT_NULL);
        strpair(PT_LOAD);
        strpair(PT_DYNAMIC);
        strpair(PT_INTERP);
        strpair(PT_NOTE);
        strpair(PT_SHLIB);
        strpair(PT_PHDR);
        strpair(PT_TLS);
        strpair(PT_GNU_EH_FRAME);
        strpair(PT_GNU_STACK);
        strpair(PT_GNU_RELRO);
        default: return "invalid program header type";
    }
}

std::ostream &operator<< (std::ostream &os, const JSON<Elf::SymbolVersioning> &vi)
{
   return JObject(os)
      // .field("versions", vi.object.versions) // XXX: map keyed by int, doesn't translate to JSON
      .field("files", vi.object.files)
      ;
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

    auto &ehdr = elf.object.getHeader();
    auto brand = ehdr.e_ident[EI_OSABI];

    auto mappedSegments = std::views::transform( elf.object.programHeaders_, [](const auto &pair) { return make_pair(programHeaderName( pair.first ), pair.second ); });
    JObject writer(os);
    writer
        .field("type", typeNames[ehdr.e_type])
        .field("entry", ehdr.e_entry)
        .field("abi", brand < sizeof abiNames / sizeof abiNames[0]? abiNames[brand] : nullptr)
        .field("sections", elf.object.sectionHeaders())
        .field("segments", mappedSegments, &elf.object)
        .field("notes", elf.object.notes())
        .field("versioninfo", elf.object.symbolVersions())
        ;

    if (elf.object.getInterpreter() != "")
        writer.field("interpreter", elf.object.getInterpreter());
    return writer;
}

std::ostream &
operator <<(std::ostream &os, const JSON<timeval> &tv)
{
    return JObject(os)
        .field("tv_sec", tv.object.tv_sec)
        .field("tv_usec", tv.object.tv_usec);
}

std::ostream &
operator <<(std::ostream &os, const JSON<Elf::auxv_t> &a)
{
    JObject writer(os);

    switch (a.object.a_type) {
#define AUX_TYPE(name, value) case value: writer.field("a_type", #name); break;
#include "libpstack/elf/auxv.h"
    default: writer.field("a_type", a.object.a_type); break;
#undef AUX_TYPE
    }
    return writer.field("a_val", a.object.a_un.a_val);
}

std::ostream &
operator <<(std::ostream &os, const JSON<Elf::Rela> &rela)
{
   return JObject(os)
      .field("r_offset", rela.object.r_offset)
      .field("r_info-sym", ELF_R_SYM(rela.object.r_info))
      .field("r_info-type", ELF_R_TYPE(rela.object.r_info));
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
operator<< (std::ostream &os, const JSON<Elf::Sym, Elf::Section> &t)
{
    auto &sec = t.context;
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
    auto &symStrings = sec.elf->getLinkedSection(sec);

    return JObject(os)
        .field("name", symStrings.io()->readString(t.object.st_name))
        .field("value", t.object.st_value)
        .field("size",t.object.st_size)
        .field("info", int(t.object.st_info))
        .field("binding", bindingNames[t.object.st_info >> 4])
        .field("type", typeNames[t.object.st_info & 0xf])
        .field("other", int(t.object.st_other))
        .field("shndx", t.object.st_shndx);
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
operator <<(std::ostream &os, const JSON<std::unique_ptr<Elf::Section>> &jsection)
{
    JObject writer(os);

    const auto &sec = jsection.object;
    const Elf::Shdr &sh = sec->shdr;

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

    writer.field("size", sh.sh_size)
        .field("uncompressedSize", sec->io()->size())
        .field("name", sec->name)
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
            writer.field("symbols", ReaderArray<Elf::Sym>(*sec->io()), *sec);
            break;
        }
        case SHT_RELA:
            writer.field("reloca", ReaderArray<Elf::Rela>(*sec->io()));
            break;
    }

    if (textContent.find(sec->name) != textContent.end()) {
        char buf[1024];
        auto count = sec->io()->read(0, std::min(sizeof buf - 1, size_t(sec->io()->size())), buf);
        buf[count] = 0;
        writer.field("content", buf);
    }
    return os;
}

/*
 * Debug output of an ELF32 program segment
 */
std::ostream &
operator<< (std::ostream &os, const JSON<Elf::Phdr, const Elf::Object *> &jo)
{
    JObject writer(os);
    auto &phdr = jo.object;

    std::set<const char *>flags;
    if (phdr.p_flags & PF_R)
        flags.insert("PF_R");

    if (phdr.p_flags & PF_W)
        flags.insert("PF_W");

    if (phdr.p_flags & PF_X)
        flags.insert("PF_X");

    writer.field("offset", phdr.p_offset)
        .field("vaddr", phdr.p_vaddr)
        .field("paddr", phdr.p_paddr)
        .field("filesz", phdr.p_filesz)
        .field("memsz", phdr.p_memsz)
        .field("type", programHeaderName(phdr.p_type))
        .field("flags", flags)
        .field("alignment", phdr.p_align);

    Elf::Off strtab = 0;
    switch (phdr.p_type) {
        case PT_DYNAMIC: {
            auto dynReader = jo.context->io->view("PT_DYNAMIC", phdr.p_offset, phdr.p_filesz);
            for (const auto & i : ReaderArray<Elf::Dyn>(*dynReader)) {
               if (i.d_tag == DT_STRTAB) {
                  strtab = i.d_un.d_ptr;
                  break;
               }
            }
            writer.field("dynamic",
                  ReaderArray<Elf::Dyn>(*dynReader), std::make_pair(jo.context, strtab));
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
    switch (tag.object.tag) {
#include "libpstack/elf/dyntag.h"
    default: return os << json(int(tag.object.tag));
    }
#undef DYN_TAG
}

std::ostream &
operator<< (std::ostream &os, const JSON<Elf::Dyn, std::pair<const Elf::Object *, Elf::Off>> &d)
{
    JObject o(os);
    o.field("tag", DynTag(d.object.d_tag))
     .field("word", d.object.d_un.d_val);

   auto stringSeg = d.context.first->getSegmentForAddress(d.context.second);
   Elf::Off strings = stringSeg->p_offset;
   strings += d.context.second - stringSeg->p_vaddr;

   auto printString = [&](const char *text) {
         o.field(text, d.context.first->io->readString(strings + d.object.d_un.d_val));
   };

   switch (d.object.d_tag) {
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
        .field("si_signo", prinfo.object.si_signo)
        .field("si_code", prinfo.object.si_code)
        .field("si_errno", prinfo.object.si_errno);
}

std::ostream &
operator <<(std::ostream &os, const JSON<prstatus_t> &jo)
{
    auto &prstatus = jo.object;
    return JObject(os)
        .field("pr_info", prstatus.pr_info)
        .field("pr_cursig", prstatus.pr_cursig)
        .field("pr_sigpend", prstatus.pr_sigpend)
        .field("pr_sighold", prstatus.pr_sighold)
        .field("pr_pid", prstatus.pr_pid)
        .field("pr_ppid", prstatus.pr_ppid)
        .field("pr_pgrp", prstatus.pr_pgrp)
        .field("pr_sid", prstatus.pr_sid)
        .field("pr_utime", prstatus.pr_utime)
        .field("pr_stime", prstatus.pr_stime)
        .field("pr_cutime", prstatus.pr_cutime)
        .field("pr_cstime", prstatus.pr_cstime)
        .field("pr_reg", intptr_t(prstatus.pr_reg))
        .field("pr_fpvalid", prstatus.pr_fpvalid);
}

std::ostream &
operator <<(std::ostream &os, const JSON<prpsinfo_t> &jo)
{
    auto &pr = jo.object;

    std::string fname = { pr.pr_fname, strnlen( pr.pr_fname, sizeof pr.pr_fname ) };
    std::string args = { pr.pr_psargs, strnlen( pr.pr_psargs, sizeof pr.pr_psargs ) };

    return JObject(os)
        .field("pr_state", int( pr.pr_state ) )
        .field("pr_sname", std::string(&pr.pr_sname, 1))
        .field("pr_zomb", bool(pr.pr_zomb))
        .field("pr_nice", int (pr.pr_nice))
        .field("pr_flag", int(pr.pr_flag))
        .field("pr_uid", pr.pr_uid )
        .field("pr_gid", pr.pr_gid )
        .field("pr_pid", pr.pr_pid )
        .field("pr_ppid", pr.pr_ppid )
        .field("pr_pgrp", pr.pr_pgrp )
        .field("pr_sid", pr.pr_sid )
        .field("pr_fname", fname )
        .field("pr_args", args )
              ;
}
}

