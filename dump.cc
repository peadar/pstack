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
    return os

        << "{ \"default_is_stmt\": " << lines.default_is_stmt
        << ", \"opcode_base\": " << int(lines.opcode_base)
        << ", \"opcode_lengths\": " << lines.opcode_lengths
        << ", \"files\": " << lines.files
        << ", \"directories\": " << lines.directories
        << ", \"matrix\": " << lines.matrix
        << "}";
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
        << " , \"linenumbers\":" << unit.lines
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
        << " , \"debug_info_offset\":" << ranges.debugInfoOffset
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
    const DwarfValue &value = attr.value;
    switch (attr.spec->form) {
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
    default: throw Exception() << "unknown DWARF attribute " << attr.spec->form;
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
   ;//  DWARFReader r(*dcie.first, dcie.second->instructions, dcie.second->end - dcie.second->instructions);
   // dwarfDumpCFAInsns(os, r);
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
    //    << ", \"instructions\": ";
    ; // DWARFReader r(*dfde.first, dfde.second->instructions, dfde.second->end - dfde.second->instructions);
    // dwarfDumpCFAInsns(os, r);
    return os << "}";
}

std::ostream &
operator << (std::ostream &os, const DwarfFrameInfo &info)
{

    os << "{ \"cielist\": [";
    const char *sep = "";
    for (auto &cieent : info.cies) {
        const DwarfCIE &cie  = cieent.second;
        os << sep << std::make_pair(info.dwarf, &cie);
        sep = ", ";
    }
    os << "], \"fdelist\": [";

    sep = "";
    for (auto &fde : info.fdeList) {
        const std::pair<const DwarfInfo *, const DwarfFDE *> p = std::make_pair(info.dwarf, &fde);
        os << sep << p;
        sep = ", ";
    }
    return os << " ] }";
}

std::ostream &
operator << (std::ostream &os, const DwarfInfo &dwarf) 
{
    os
        << "{ \"units\": " << dwarf.units()
        << ", \"pubnameUnits\": " << dwarf.pubnames()
        << ", \"aranges\": " << dwarf.ranges();

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

    auto ehdr = obj.getElfHeader();

    size_t brand = ehdr.e_ident[EI_OSABI];
    os << "{ \"type\": \"" << typeNames[ehdr.e_type] << "\", \"entry\": " <<  ehdr.e_entry << ", \"abi\": ";
    if (brand >= 0 && brand < sizeof abiNames / sizeof abiNames[0])
        os << "\"" << abiNames[brand] << "\"";
    else
        os << brand;

    os << ", \"sections\": [";
    const char *sep = "";
    for (auto &i : obj.getSections()) {
        os << sep << std::make_pair<const ElfObject *, const Elf_Shdr *> (&obj, &i);
        sep = ", ";
    }
    os << "]";


    os << ", \"segments\": " << obj.getSegments();


    for (auto seg : obj.getSegments()) {

        if (seg.p_type == PT_DYNAMIC) {
            os << ", \"dynamic\": [";
            const char *sep = "";
            off_t dynoff = seg.p_offset;
            off_t edyn = dynoff + seg.p_filesz;
            for (; dynoff < edyn; dynoff += sizeof (Elf_Dyn)) {
                Elf_Dyn dyn;
                obj.io->readObj(dynoff, &dyn);
                os << sep << dyn;
                sep = ", ";
            }
            os << "]";
            break;
        }
    }

    os << ", \"interpreter\": \"" << obj.getInterpreter() << "\"";

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
         os << " }";
        return NOTE_CONTIN;
    });
    os << "]";
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
        << "{ \"a_type\": ";
    switch (a.a_type) {
#define AUX_TYPE(name, value) case value: os << "\"" << #name << "\""; break;
#include "elf/aux.h"
    default: os << a.a_type; break;
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
        << ", \"pr_reg\": " << intptr_t(prstat.pr_reg)
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
    const Elf_Shdr *strs = o->getElfHeader().e_shstrndx == SHN_UNDEF ?  0 : o->getSection(o->getElfHeader().e_shstrndx);

    os << "{ \"size\":" << h->sh_size;
    if (strs)
        os << ", \"name\": \"" << o->io->readString(strs->sh_offset + h->sh_name) << "\"";
        
    os << ", \"type\": ";
    if (h->sh_type <= SHT_DYNSYM)
        os << "\"" << sectionTypeNames[h->sh_type] << "\"";
    else
        os << h->sh_type;

   
    std::string sep = "";

    os << ", \"flags\": " << "[";
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
            o->io->readObj(symoff, &sym);
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

    off_t symStrings = o->getSection(h->sh_link)->sh_offset;
    return os << "{ \"name\": \"" << o->io->readString(symStrings + s->st_name) << "\""
       << ", \"value\": " << s->st_value
       << ", \"size\": " << s->st_size
       << ", \"info\": " << (int)s->st_info
       << ", \"binding\": \"" << bindingNames[s->st_info >> 4] << "\""
       << ", \"type\": \"" << typeNames[s->st_info & 0xf] << "\""
       << ", \"other\": " << (int)s->st_other
       << ", \"shndx\": " << s->st_shndx
       << " }";

}

struct DynTag {
    long long tag;
    DynTag(long long tag_) : tag(tag_) {}
};
std::ostream &
operator << (std::ostream &os, DynTag tag)
{
#define T(a) case a: return os << #a;
    switch (tag.tag) {
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
    default: return os << "unknown " << tag;
    }
#undef T
}

std::ostream &
operator<< (std::ostream &os, const Elf_Dyn &d)
{
    os << "{ \"tag\": \"" << DynTag(d.d_tag) << "\"";
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

#define T(a, b) case a: return os << #a " (" b ")";
std::ostream &operator << (std::ostream &os, td_err_e err)
{
switch (err) {
T(TD_OK, "No error.")
T(TD_ERR, "No further specified error.")
T(TD_NOTHR, "No matching thread found.")
T(TD_NOSV, "No matching synchronization handle found.")
T(TD_NOLWP, "No matching light-weighted process found.")
T(TD_BADPH, "Invalid process handle.")
T(TD_BADTH, "Invalid thread handle.")
T(TD_BADSH, "Invalid synchronization handle.")
T(TD_BADTA, "Invalid thread agent.")
T(TD_BADKEY, "Invalid key.")
T(TD_NOMSG, "No event available.")
T(TD_NOFPREGS, "No floating-point register content available.")
T(TD_NOLIBTHREAD, "Application not linked with thread library.")
T(TD_NOEVENT, "Requested event is not supported.")
T(TD_NOCAPAB, "Capability not available.")
T(TD_DBERR, "Internal debug library error.")
T(TD_NOAPLIC, "Operation is not applicable.")
T(TD_NOTSD, "No thread-specific data available.")
T(TD_MALLOC, "Out of memory.")
T(TD_PARTIALREG, "Not entire register set was read or written.")
T(TD_NOXREGS, "X register set not available for given thread.")
T(TD_TLSDEFER, "Thread has not yet allocated TLS for given module.")
T(TD_VERSION, "Version if libpthread and libthread_db do not match.")
T(TD_NOTLS, "There is no TLS segment in the given module.")
default: return os << "unknown TD error " << int(err);
}
}
#undef T

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


