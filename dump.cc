#include "dump.h"

static void dwarfDumpCFAInsns(std::ostream &os, DWARFReader &r);


std::ostream &operator << (std::ostream &os, const DwarfFileEntry &fe) {
    return os
        << "{ \"name\": \"" << fe.name << "\""
        << ", \"dir\": \"" << fe.directory << "\""
        << ", \"lastmod\": " << fe.lastMod
        << "}";
}

std::ostream &operator << (std::ostream &os, const DwarfLineState &ls) {
    return os
        << "{ \"file\": " << *ls.file
        << ", \"line\": " << ls.line
        << ", \"addr\": " << ls.addr
        << "}";
}

std::ostream &operator << (std::ostream &os, const DwarfLineInfo &lines) {
    return os << lines.matrix;
}

std::ostream & operator << (std::ostream &os, const DwarfEntry &entry) {
    os
        << "{ \"type\": \"" << entry.type->tag << "\""
        << ", \"attributes\": " << entry.attributes;

    if (entry.type->hasChildren)
        os << ", \"children\": " << entry.children;

    return os
        << " }";
}

std::ostream &operator << (std::ostream &os, const DwarfAttributeSpec &spec) {
    return os
        << "{ \"name\": " << spec.name
        << ", \"form\": " << spec.form
        << "}";
}

std::ostream & operator << (std::ostream &os, const DwarfAbbreviation &abbr) {
    return os
        << " { \"code\": " << abbr.code 
        << " , \"has_children\": " << (abbr.hasChildren ? "true" : "false")
        << " , \"specs\": " << abbr.specs
        << " }";
}

std::ostream &operator << (std::ostream &os, const DwarfUnit &unit) {
    return os
        << " { \"length\":" <<  unit.length
        << " , \"version\":" <<  int(unit.version)
        << " , \"addrlen\":" <<  int(unit.addrlen)
        << " , \"linenumbers\":" << *unit.lines
        << " , \"entries\":" <<  unit.entries
        << " }";
}

std::ostream & operator << (std::ostream &os, const DwarfARange &range) {
    return os 
        << " { \"start\":" << range.start
        << " , \"length\":" << range.length
        << " }";
}

std::ostream & operator << (std::ostream &os, const DwarfARangeSet &ranges) {
    return os 
        << " { \"length\":" << ranges.length
        << " , \"version\":" << int(ranges.version)
        << " , \"addrlen\":" << int(ranges.addrlen)
        << " , \"descrlen\":" <<  int(ranges.segdesclen)
        << " , \"ranges\":" <<  ranges.ranges
        << " }";
}

std::ostream & operator << (std::ostream &os, DwarfTag tag) {
#define DWARF_TAG(x,y) case x: return os << #x;
    switch (tag) {
#include "dwarf/tags.h"
    default: return os << int(tag);
    }
#undef DWARF_TAG
}

std::ostream &operator << (std::ostream &os, DwarfLineEOpcode code) {
#define DWARF_LINE_E(x,y) case x: return os << "\"" #x "\"";
    switch (code) {
#include "dwarf/line_e.h"
    default: return os << int(code);
    }
#undef DWARF_LINE_E
}

std::ostream &operator << (std::ostream &os, DwarfForm code) {
#define DWARF_FORM(x,y) case x: return os << #x;
    switch (code) {
#include "dwarf/forms.h"
    default: return os << "(unknown)";
    }
#undef DWARF_FORM
}

std::ostream &operator << (std::ostream &os, DwarfAttrName code) {
#define DWARF_ATTR(x,y) case x: return os <<  #x ;
    switch (code) {
#include "dwarf/attr.h"
    default: return os << int(code);
    }
#undef DWARF_ATTR
}

std::ostream &operator << (std::ostream &os, const DwarfPubname &name) {
    return os
        << " { \"offset\": " << name.offset
        << " , \"name\": " << name.name
        << " }";
}

std::ostream &operator << (std::ostream &os, const DwarfPubnameUnit &unit) {
    return os
        << " { \"length\": " << unit.length
        << " , \"version\": " << unit.version
        << " , \"info offset\": " << unit.infoOffset
        << " , \"info size\":" <<  unit.infoLength
        << " , \"names\": " << unit.pubnames
        << " }";
}

std::ostream &
operator << (std::ostream &os, const DwarfBlock &b)
{
    return os << "[ " << b.offset << ", " << b.length << "]";
}

std::ostream &
operator << (std::ostream &os, const DwarfAttribute &attr)
{
    const DwarfAttributeSpec *type = attr.spec;
    const DwarfValue &value = attr.value;
    switch (type->form) {
    case DW_FORM_addr: os << value.addr; break;
    case DW_FORM_data1: os << int(value.data1); break;
    case DW_FORM_data2: os << value.data2; break;
    case DW_FORM_data4: os << value.data4; break;
    case DW_FORM_data8: os << value.data8; break;
    case DW_FORM_sdata: os << value.sdata; break;
    case DW_FORM_udata: os << value.udata; break;
    case DW_FORM_string: case DW_FORM_strp: os << "\"" << value.string << "\""; break;
    case DW_FORM_ref2: os << "\"@" << value.ref2 << "\""; break;
    case DW_FORM_ref4: os << "\"@" << value.ref4 << "\""; break;
    case DW_FORM_ref8: os << "\"@" << value.ref8 << "\""; break;
    case DW_FORM_block1: case DW_FORM_block2: case DW_FORM_block4: case DW_FORM_block: os << value.block; break;
    case DW_FORM_flag: os << (value.flag ? "true" : "false"); break;
    default: throw type->form;
    }
    return os;
}

std::ostream &
operator <<(std::ostream &os, const std::pair<const DwarfInfo *, const DwarfCIE *> &dcie)
{
    os
        << "{ \"version\": " << int(dcie.second->version)
        << ", \"augmentation\": \"" << dcie.second->augmentation << "\""
        << ", \"codeAlign\":" << dcie.second->codeAlign
        << ", \"dataAlign\": " << dcie.second->dataAlign
        << ", \"return address reg\": " << dcie.second->rar
        << ", \"augsize\": " <<  dcie.second->augSize
        << ", \"instrlen\": " << dcie.second->end - dcie.second->instructions
        << ", \"instructions\": ";
    DWARFReader r(*dcie.first, dcie.second->instructions, dcie.second->end - dcie.second->instructions);
    dwarfDumpCFAInsns(os, r);
    return os
        << " }";
}

std::ostream &
operator << (std::ostream &os, const std::pair<const DwarfInfo *, const DwarfFDE *> &dfde )
{
    os
        << "{ \"cie\": " << intptr_t(dfde.second->cie)
        << ", \"loc\": " << dfde.second->iloc
        << ", \"range\": " << dfde.second->irange
        << ", \"auglen\": " << dfde.second->aug.size()
        << ", \"instructions\": ";
    DWARFReader r(*dfde.first, dfde.second->instructions, dfde.second->end - dfde.second->instructions);
    dwarfDumpCFAInsns(os, r);
    return os << "}";
}

std::ostream &
operator << (std::ostream &os, const DwarfFrameInfo &info)
{

    os << "{ \"cielist\": [";
    const char *sep = "";
    for (auto cie : info.cies) {
        const std::pair<const DwarfInfo *, const DwarfCIE *> pair = std::make_pair(info.dwarf, cie.second);
        os << sep << pair;
        sep = ", ";
    }
    os << "], \"fdelist\": [";

    sep = "";
    for (auto fde : info.fdeList) {
        const std::pair<const DwarfInfo *, const DwarfFDE *> p = std::make_pair(info.dwarf, fde);
        os << sep << p;
        sep = ", ";
    }
    return os << " ] }";
}

std::ostream &
operator << (std::ostream &os, const DwarfInfo &dwarf) 
{
    os
        << "{ \"units\": " << dwarf.units
        << ", \"pubnameUnits\": " << dwarf.pubnameUnits
        << ", \"aranges\": " << dwarf.aranges;

    if (dwarf.debugFrame)
        os << ", \"debugframe\": " << *dwarf.debugFrame;

    if (dwarf.ehFrame)
        os << ", \"ehFrame\": " << *dwarf.ehFrame;
    return os << "}";
}

static void
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
                    << ", \"arg\":"
                    << r.getuint(r.version >= 3 ? r.addrLen : 4); break;
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

            case 0x2e: os << "\"DW_CFA_GNU_args_size\"" << ", \"offset\":" << r.getuleb128(); break;
            case 0x2d: os << "\"DW_CFA_GNU_window_size\""; break;
            case 0x2f: os << "\"DW_CFA_GNU_negative_offset_extended\""; break;
            default: throw "unknown CFA op";
            break;
        }
    }
    os << " }";
}

static void
dwarfDumpCFAInsns(std::ostream &os, DWARFReader &r)
{
    os << "[ ";
    std::string sep = "";
    while (!r.empty()) {
        os << sep;
        dwarfDumpCFAInsn(os, r);
        sep = ", ";
    } 
    os << "]";
}

/*
 * Debug output of an ELF32 object.
 */
std::ostream &operator<< (std::ostream &os, const ElfObject &obj)
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

    const Elf_Ehdr &ehdr = obj.elfHeader;

    size_t brand = ehdr.e_ident[EI_OSABI];
    os << "{ \"type\": \"" << typeNames[ehdr.e_type] << "\", \"entry\": " <<  ehdr.e_entry << ", \"abi\": ";
    if (brand >= 0 && brand < sizeof abiNames / sizeof abiNames[0])
        os << "\"" << abiNames[brand] << "\"";
    else
        os << brand;

    os << ", \"sections\": [";
    const char *sep = "";
    for (auto i : obj.sectionHeaders) {
        os << sep << std::make_pair<const ElfObject *, const Elf_Shdr *> (&obj, i);
        sep = ", ";
    }
    os << "]";


    os << ", \"segments\": " << obj.programHeaders;

    if (obj.dynamic) {
        os << ", \"dynamic\": [";
        const char *sep = "";
        off_t dynoff = obj.dynamic->p_offset;
        off_t edyn = dynoff + obj.dynamic->p_filesz;
        for (; dynoff < edyn; dynoff += sizeof (Elf_Dyn)) {
            Elf_Dyn dyn;
            obj.io.readObj(dynoff, &dyn);
            os << sep << dyn;
            sep = ", ";
        }
        os << "]";
    }
    if (obj.interpreterName != "")
        os << ", \"interpreter\": \"" << obj.interpreterName << "\"";


    sep = "";
    os << ", \"notes\": [";
    obj.getNotes([&obj, &os, &sep] (const char *name, u_int32_t type, const void *datap, size_t len) -> NoteIter {
        os << sep;
        sep = ", ";

        os
            << "{ \"name\": \"" << name << "\""
            << ", \"type\": \"" << type << "\"";


        switch (type) {
            case NT_PRSTATUS: {
                const prstatus_t *prstatus = (const prstatus_t *)datap;
                os << ", \"prstatus\": " << *prstatus;
            }
            break;
            case NT_AUXV: {
                const Elf_auxv_t *aux = (const Elf_auxv_t *)datap;
                const Elf_auxv_t *eaux = aux + len / sizeof *aux;
                const char *sep = "";
                os << ", \"auxv\": [";
                while (aux < eaux) {
                    os << sep;
                    sep = ", ";
                    os << *aux;
                    aux++;
                }
                os << "]";
            }
            break;
        }
        return NOTE_CONTIN;
    });

    if (obj.dwarf)
        os << ", \"dwarf\": " << *obj.dwarf;

    return os << "}";
}

std::ostream &
operator <<(std::ostream &os, const elf_siginfo &prinfo)
{
    return os
        << "{ \"si_signo\": " << prinfo.si_signo
        << ", \"si_code\": " << prinfo.si_code
        << ", \"si_errno\": " << prinfo.si_errno
        << " }";
}

std::ostream &
operator <<(std::ostream &os, const timeval &tv)
{
    return os
        << "{ \"tv_sec\": " << tv.tv_sec
        << ", \"tv_usec\": " << tv.tv_usec
        << "}";
}

std::ostream &
operator <<(std::ostream &os, const Elf_auxv_t &a)
{
    os
        << "{ \"a_type\": " << a.a_type;
    switch (a.a_type) {
#define AUX_TYPE(name, value) case value: os << #name; break;
#include "elf/aux.h"
#undef AUX_TYPE
    }
    return os
        << ", \"a_val\": " << a.a_un.a_val
        << "}";
}

std::ostream &
operator <<(std::ostream &os, const prstatus_t &prstat)
{
    return os
        << "{ \"pr_info\": " << prstat.pr_info
        << ", \"pr_cursig\": " << prstat.pr_cursig
        << ", \"pr_sigpend\": " << prstat.pr_sigpend
        << ", \"pr_sighold\": " << prstat.pr_sighold
        << ", \"pr_pid\": " << prstat.pr_pid
        << ", \"pr_ppid\": " << prstat.pr_ppid
        << ", \"pr_pgrp\": " << prstat.pr_pgrp
        << ", \"pr_sid\": " << prstat.pr_sid
        << ", \"pr_utime\": " << prstat.pr_utime
        << ", \"pr_stime\": " << prstat.pr_stime
        << ", \"pr_cutime\": " << prstat.pr_cutime
        << ", \"pr_cstime\": " << prstat.pr_cstime
        << ", \"pr_reg\": " << prstat.pr_reg
        << ", \"pr_fpvalid\": " << prstat.pr_fpvalid
        << "}";
}

std::ostream &
operator <<(std::ostream &os, const std::pair<const ElfObject *, const Elf_Shdr *> &p)
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

    const ElfObject *o = p.first;
    const Elf_Shdr *h = p.second;

    os << "{ \"name\": \"" << o->readString(o->sectionStrings + h->sh_name) << "\"" << ", \"type\": ";
            
    if (h->sh_type <= SHT_DYNSYM)
        os << "\"" << sectionTypeNames[h->sh_type] << "\"";
    else
        os << h->sh_type;

    os << ", \"flags\": " << "[";
   
    std::string sep = "";

    if (h->sh_flags & SHF_WRITE) {
        os << sep << "\"write\"";
        sep = ", ";
    }

    if (h->sh_flags & SHF_ALLOC) {
        os << sep << "\"alloc\"";
        sep = ", ";
    }

    if (h->sh_flags & SHF_WRITE) {
        os << sep << "\"exec\"";
        sep = ", ";
    }
    os
        << "]"
        << ", \"address\": " << h->sh_addr
        << ", \"offset\": " << h->sh_offset
        << ", \"size\":" << h->sh_size
        << ", \"link\":" << h->sh_link
        << ", \"info\":" << h->sh_info;

    switch (h->sh_type) {
    case SHT_SYMTAB:
    case SHT_DYNSYM:
        off_t symoff = h->sh_offset;
        off_t esym = symoff + h->sh_size;
        os << ", \"symbols\": [";
        std::string sep = "";
        for (; symoff < esym; symoff += sizeof (Elf_Sym)) {
            Elf_Sym sym;
            o->io.readObj(symoff, &sym);
            std::tuple<const ElfObject *, const Elf_Shdr *, const Elf_Sym *> t = std::make_tuple(o, h, &sym);
            os << sep << t;
            sep = ", ";
        }
        os << "]";
        break;
    }
    return os << " }";
}

/*
 * Debug output of an ELF32 program segment
 */
std::ostream &
operator<< (std::ostream &os, const Elf_Phdr &h)
{

    static const char *segmentTypeNames[] = {
            "PT_NULL",
            "PT_LOAD",
            "PT_DYNAMIC",
            "PT_INTERP",
            "PT_NOTE",
            "PT_SHLIB",
            "PT_PHDR"
    };

    os << "{ \"type\": ";
    if (h.p_type <= PT_PHDR)
        os << "\"" << segmentTypeNames[h.p_type] << "\"";
    else
        os << h.p_type;

    os
        << ", \"offset\": " << h.p_offset
        << ", \"vaddr\": " << h.p_vaddr
        << ", \"paddr\": " << h.p_paddr
        << ", \"filesz\": " << h.p_filesz
        << ", \"memsz\": " << h.p_memsz
        << ", \"flags\": [";

    std::string sep = "";

    if (h.p_flags & PF_R) {
        os << sep << "\"PF_R\"";
        sep = ", ";
    }

    if (h.p_flags & PF_W) {
        os << sep << "\"PF_W\"";
        sep = ", ";
    }

    if (h.p_flags & PF_X) {
        os << sep << "\"PF_X\"";
        sep = ", ";
    }
    return os << "], \"alignment\": " << h.p_align << " }";
}

/*
 * Debug output of an Elf symbol.
 */
std::ostream &
operator<< (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr *, const Elf_Sym *> &t)
{
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

    const ElfObject *o = std::get<0>(t);
    const Elf_Shdr *h = std::get<1>(t);
    const Elf_Sym *s = std::get<2>(t);

    off_t symStrings = o->sectionHeaders[h->sh_link]->sh_offset;
    return os << "{ \"name\": \"" << o->readString(symStrings + s->st_name) << "\""
       << ", \"value\": " << s->st_value
       << ", \"size\": " << s->st_size
       << ", \"info\": " << (int)s->st_info
       << ", \"binding\": \"" << bindingNames[s->st_info >> 4] << "\""
       << ", \"type\": \"" << typeNames[s->st_info & 0xf] << "\""
       << ", \"other\": " << (int)s->st_other
       << ", \"shndx\": " << s->st_shndx
       << " }";

}

std::ostream &
operator<< (std::ostream &os, const Elf_Dyn &d)
{
    static const char *tagNames[] = {
        "DT_NULL",
        "DT_NEEDED",
        "DT_PLTRELSZ",
        "DT_PLTGOT",
        "DT_HASH",
        "DT_STRTAB",
        "DT_SYMTAB",
        "DT_RELA",
        "DT_RELASZ",
        "DT_RELAENT",
        "DT_STRSZ",
        "DT_SYMENT",
        "DT_INIT",
        "DT_FINI",
        "DT_SONAME",
        "DT_RPATH",
        "DT_SYMBOLIC",
        "DT_REL",
        "DT_RELSZ",
        "DT_RELENT",
        "DT_PLTREL",
        "DT_DEBUG",
        "DT_TEXTREL",
        "DT_JMPREL",
        "DT_BIND_NOW"
    };
    os
        << "{ \"tag\": ";
    if (d.d_tag >= 0 && d.d_tag <= DT_BIND_NOW)
        os << "\"" << tagNames[d.d_tag] << "\"";
    else
        os << d.d_tag;
    return os << ", \"word\": " << d.d_un.d_val << " }";
}


std::ostream &
operator<< (std::ostream &os, DwarfExpressionOp op)
{
#define DWARF_OP(name, value, args) case name: return os << #name;
    switch (op) {
#include "dwarf/ops.h"
        default: return os << "(unknown operation)";
    }
#undef DWARF_OP
}

#ifdef NOTYET

static const char *
auxTypeName(int t)
{
#define T(name) case name: return #name;
    switch (t) {
         T(AT_IGNORE)
         T(AT_EXECFD)
         T(AT_PHDR)
         T(AT_PHENT)
         T(AT_PHNUM)
         T(AT_PAGESZ)
         T(AT_BASE)
         T(AT_FLAGS)
         T(AT_ENTRY)
         T(AT_NOTELF)
         T(AT_UID)
         T(AT_EUID)
         T(AT_GID)
         T(AT_EGID)
         T(AT_CLKTCK)
         T(AT_SYSINFO)
         T(AT_SYSINFO_EHDR)
         default: return "unknown";
    }
#undef T
}

#define T(a) case a: return #a;
static const char *
DW_EH_PE_typeStr(unsigned char c)
{
    switch (c & 0xf) {
        T(DW_EH_PE_absptr)
        T(DW_EH_PE_uleb128)
        T(DW_EH_PE_udata2)
        T(DW_EH_PE_udata4)
        T(DW_EH_PE_udata8)
        T(DW_EH_PE_sleb128)
        T(DW_EH_PE_sdata2)
        T(DW_EH_PE_sdata4)
        T(DW_EH_PE_sdata8)
        default: return "(unknown)";
    }
}

static const char *
DW_EH_PE_relStr(unsigned char c)
{
    switch (c & 0xf0) {
    T(DW_EH_PE_pcrel)
    T(DW_EH_PE_textrel)
    T(DW_EH_PE_datarel)
    T(DW_EH_PE_funcrel)
    T(DW_EH_PE_aligned)
    default: return "(unknown)";
    }

}
#undef T



#endif


