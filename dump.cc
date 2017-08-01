#include <libpstack/dump.h>
#include <sys/procfs.h>
#include <cassert>

#if ELF_BITS == 64
#define ELF_R_SYM(a) ELF64_R_SYM(a)
#define ELF_R_TYPE(a) ELF64_R_TYPE(a)
#elif ELF_BITS == 32
#define ELF_R_SYM(a) ELF32_R_SYM(a)
#define ELF_R_TYPE(a) ELF32_R_TYPE(a)
#else
#error "Non-32, non-64-bit platform?"
#endif

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
        << "{ \"name\": " << "\"" << spec.name << "\""
        << ", \"form\": " << "\"" << spec.form << "\""
        << "}";
}

std::ostream & operator << (std::ostream &os, const DwarfAbbreviation &abbr) {
    return os
        << " { \"code\": " << abbr.code
        << " , \"has_children\": " << (abbr.hasChildren ? "true" : "false")
        << " , \"specs\": " << abbr.specs
        << " }";
}

std::ostream &operator << (std::ostream &os, const std::shared_ptr<DwarfUnit> &unit) {
    return os << *unit;
}
std::ostream &operator << (std::ostream &os, const DwarfUnit &unit) {
    return os
        << " { \"length\":" <<  unit.length
        << " , \"offset\":" <<  unit.offset
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
#include <libpstack/dwarf/tags.h>
    default: return os << int(tag);
    }
#undef DWARF_TAG
}

std::ostream &operator << (std::ostream &os, DwarfLineEOpcode code) {
#define DWARF_LINE_E(x,y) case x: return os << "\"" #x "\"";
    switch (code) {
#include <libpstack/dwarf/line_e.h>
    default: return os << int(code);
    }
#undef DWARF_LINE_E
}

std::ostream &operator << (std::ostream &os, DwarfForm code) {
#define DWARF_FORM(x,y) case x: return os << #x;
    switch (code) {
#include <libpstack/dwarf/forms.h>
    default: return os << "(unknown)";
    }
#undef DWARF_FORM
}

std::ostream &operator << (std::ostream &os, DwarfAttrName code) {
#define DWARF_ATTR(x,y) case x: return os <<  #x ;
    switch (code) {
#include <libpstack/dwarf/attr.h>
    default: return os << int(code);
    }
#undef DWARF_ATTR
}

std::ostream &operator << (std::ostream &os, const DwarfPubname &name) {
    return os
        << " { \"offset\": " << name.offset
        << " , \"name\": \"" << name.name << "\""
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
    auto dwarf = attr.entry->unit->dwarf;
    auto elf = dwarf->elf;
    os << "[ " << *attr.spec << ",";
    switch (attr.spec->form) {
    case DW_FORM_addr:
        os << value.addr;
        break;

    case DW_FORM_sdata:
        os << value.sdata;
        break;

    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_sec_offset:
    case DW_FORM_udata:
        os << value.udata;
        break;
    case DW_FORM_GNU_strp_alt:
    case DW_FORM_string:
    case DW_FORM_strp:
        os << "\"" << value.string << "\"";
        break;
    case DW_FORM_ref_addr:
    case DW_FORM_ref2:
    case DW_FORM_ref4:
    case DW_FORM_ref8:
    case DW_FORM_ref_udata: {
        const auto entry = attr.entry->referencedEntry(attr.spec->name);
        if (entry)
            os << "\"ref to " << entry->name() << " at " << entry->offset << "\"";
        else
            os << "\"HAVENOTIT@" << value.addr <<  " + " << attr.entry->unit->offset << " = "  << (value.addr + attr.entry->unit->offset)   << "\"";
        break;
    }
    case DW_FORM_GNU_ref_alt: {
        os << "\"alt ref\"";
                                 /*
        auto altDwarf = dwarf->getAltDwarf();
        auto section = altDwarf->elf->getSection(".debug_info", 0);
        auto off = attr.value.ref;
        const auto &allEntries = altDwarf->allEntries;
        const auto &entry = allEntries.find(off);
        if (entry != allEntries.end())
            os << "\"alt ref to " << entry->second->name() << " at " << off << " in " << altDwarf->elf->io->describe() <<"\"";
        else
            os << "\"HAVENOTIT@" << off << (abort(),0) << "\"";
        */
        break;
    }
    case DW_FORM_exprloc:
    case DW_FORM_block1:
    case DW_FORM_block2:
    case DW_FORM_block4:
    case DW_FORM_block:
        os << value.block;
        break;
    case DW_FORM_flag:
        os << (value.flag ? "true" : "false");
        break;
    case DW_FORM_flag_present:
        os << "true";
        break;
    default: os << "\"unknown DWARF form " << attr.spec->form << "\"";
    }
    os << " ] ";
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
        << ", \"instrlen\": " << dcie.second->end - dcie.second->instructions
        << ", \"instructions\": ";
   ;
   DWARFReader r(dcie.first->elf->io, dcie.second->instructions, dcie.second->end - dcie.second->instructions, ELF_BITS / 8);
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
        << ", \"augmentation\": \"" << dfde.second->augmentation << "\""
        << ", \"instructions\": "
    ; 
    DWARFReader r(dfde.first->elf->io, dfde.second->instructions, dfde.second->end - dfde.second->instructions, ELF_BITS/8);
    dwarfDumpCFAInsns(os, r);
    return os << "}";
}

std::ostream &
operator << (std::ostream &os, const DwarfFrameInfo &info)
{

    os << "{ \"cielist\": [";
    const char *sep = "";
    for (auto cieent = info.cies.begin(); cieent != info.cies.end(); ++cieent) {
        const DwarfCIE &cie  = cieent->second;
        os << sep << std::make_pair(info.dwarf, &cie);
        sep = ",\n";
    }
    os << "], \"fdelist\": [";

    sep = "";
    for (auto fde = info.fdeList.begin(); fde != info.fdeList.end(); ++ fde) {
        const std::pair<const DwarfInfo *, const DwarfFDE *> p = std::make_pair(info.dwarf, &(*fde));
        os << sep << p;
        sep = ",\n";
    }
    return os << " ] }";
}

std::ostream &
operator << (std::ostream &os, DwarfInfo &dwarf)
{
    os
        << "{ \"units\": " << dwarf.getUnits()
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

static void
dwarfDumpCFAInsns(std::ostream &os, DWARFReader &r)
{
    os << "[ ";
    std::string sep = "";
    while (!r.empty()) {
        os << sep;
        dwarfDumpCFAInsn(os, r);
        sep = ",\n";
    }
    os << "]";
}



void printNote(std::ostream &os, const ElfNoteDesc &note) {
     os
         << "{ \"name\": \"" << note.name() << "\""
         << ", \"type\": \"" << note.type() << "\"";

     // need to switch on type and name for notes.
     if (note.name() == "CORE") {
         const unsigned char *datap = note.data();
         size_t len = note.size();
         switch (note.type()) {
             case NT_PRSTATUS: {
                 assert(len >= sizeof (prstatus_t));
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
                     sep = ",\n";
                     os << *aux;
                     aux++;
                 }
                 os << "]";
             }
             break;
         }
     }
     os << " }";
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
    auto brand = ehdr.e_ident[EI_OSABI];
    os << "{ \"type\": \"" << typeNames[ehdr.e_type] << "\", \"entry\": " <<  ehdr.e_entry << ", \"abi\": ";
    if (brand < sizeof abiNames / sizeof abiNames[0])
        os << "\"" << abiNames[brand] << "\"";
    else
        os << brand;

    os << ", \"sections\": [";
    const char *sep = "";
    for (auto &i : obj.getSections()) {
        os << sep << ElfSection(obj, &i);
        sep = ",\n";
    }
    os << "]";


    os << ", \"segments\": " << obj.programHeaders;


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

    os << ", \"interpreter\": \"" << obj.getInterpreter() << "\"";

    sep = "";
    os << ", \"notes\": [";
    for (const auto note : obj.notes) {
        os << sep;
        sep = ",\n";
       printNote(os, note);
    }

    os << "]";
    return os << "}";
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
operator <<(std::ostream &os, const Elf_Rela &rela)
{

   return os
      << "{ \"r_offset\": " << rela.r_offset
         << ", \"r_info\": { "
            << ", \"SYM\": " << ELF_R_SYM(rela.r_info)
            << ", \"TYPE\": " << ELF_R_TYPE(rela.r_info)
         << "} "
      << "} ";
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

std::ostream &
operator <<(std::ostream &os, const ElfSection &sec)
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

    auto &o = sec.obj;
    const Elf_Shdr *h = sec.shdr;
    const Elf_Shdr *strs = o.getElfHeader().e_shstrndx == SHN_UNDEF ?  0 : &o.sectionHeaders[o.getElfHeader().e_shstrndx];

    os << "{ \"size\":" << h->sh_size;
    if (strs)
        os << ", \"name\": \"" << o.io->readString(strs->sh_offset + h->sh_name) << "\"";

    os << ", \"type\": ";
    if (h->sh_type <= SHT_DYNSYM)
        os << "\"" << sectionTypeNames[h->sh_type] << "\"";
    else
        os << h->sh_type;

    os << ", \"flags\": " << "[";

    std::string sep = "";
    for (auto i = sh_flag_names; i->name; ++i) {
        if (h->sh_flags & i->value) {
            os << sep << "\"" << i->name << "\"";
            sep = ", ";
        }
    }
    os
        << "]"
        << ", \"address\": " << h->sh_addr
        << ", \"offset\": " << h->sh_offset
        << ", \"link\":" << h->sh_link
        << ", \"info\":" << h->sh_info;

    switch (h->sh_type) {
        case SHT_SYMTAB:
        case SHT_DYNSYM: {
            off_t symoff = h->sh_offset;
            off_t esym = symoff + h->sh_size;
            os << ", \"symbols\": [";
            std::string sep = "";
            for (; symoff < esym; symoff += sizeof (Elf_Sym)) {
                Elf_Sym sym;
                o.io->readObj(symoff, &sym);
                std::pair<const ElfSection &, const Elf_Sym *> t = std::make_pair(std::ref(sec), &sym);
                os << sep << t;
                sep = ",\n";
            }
            os << "]";
            break;
        }
        case SHT_RELA: {
            os << ", \"reloca\": [";
            off_t off = h->sh_offset;
            const char *sep = "";
            for (off_t esym = off + h->sh_size; off < esym; off += sizeof (Elf_Rela)) {
                Elf_Rela rela;
                o.io->readObj(off, &rela);
                os << sep << rela;
                sep = ",\n";
            }
            os << "]";
        }
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
operator<< (std::ostream &os, std::pair<const ElfSection &, const Elf_Sym *> &t)
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

    auto sec = t.first;
    const Elf_Sym *s = t.second;

    off_t symStrings = sec.getLink()->sh_offset;
    return os << "{ \"name\": \"" << sec.obj.io->readString(symStrings + s->st_name) << "\""
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
    default: return os << "unknown " << tag.tag;
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
#include <libpstack/dwarf/ops.h>
        default: return os << "(unknown operation)";
    }
#undef DWARF_OP
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



