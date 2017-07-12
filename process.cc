#include <set>
#include <iomanip>
#include <limits>
#include <cassert>
#include <limits>
#include <limits.h>
#include <iostream>
#include <link.h>
#include <unistd.h>
#include <libpstack/ps_callback.h>
#include <libpstack/proc.h>
#include <libpstack/dwarf.h>
#include <libpstack/dump.h>

typedef struct regs ptrace_regs;

#ifdef __FreeBSD__
#ifdef __i386__
#define REG(regs, reg) (regs.r_e##reg)
#endif

#ifdef __amd64__
#define REG(regs, reg) (regs.r_r##reg)
#endif
#endif


#ifdef __linux__
typedef struct user_regs_struct  elf_regs;
#if defined(__PPC)
#define REG(regs, reg) ((regs).n##reg)
#elif defined(__i386__)
#define REG(regs, reg) ((regs).e##reg)
#else
#define REG(regs, reg) ((regs).r##reg)
#endif
#else
#error "not linux?"
#endif

static size_t gMaxFrames = 1024; /* max number of frames to read */

void
PstackOptions::operator += (PstackOption opt)
{
    values.set(opt);
}

void
PstackOptions::operator -= (PstackOption opt)
{
    values.reset(opt);
}

bool
PstackOptions::operator () (PstackOption opt) const
{
    return values[opt];
}

template <typename T> static void
delall(T &container)
{
    for (auto i = container.begin(); i != container.end(); ++i)
        delete *i;
}

Process::Process(std::shared_ptr<ElfObject> exec, std::shared_ptr<Reader> io_, const PathReplacementList &prl)
    : entry(0)
    , vdso(0)
    , isStatic(false)
    , sysent(0)
    , agent(0)
    , execImage(exec)
    , pathReplacements(prl)
    , io(std::make_shared<CacheReader>(io_))
{
   if (exec)
      entry = exec->getElfHeader().e_entry;
}

void
Process::load()
{

    /*
     * Attach the executable and any shared libs.
     * The process is still running here, but unless its actively loading or
     * unload a shared library, this relatively safe, and saves us a lot of
     * work while the process is stopped.
     */

    if (!execImage)
        throw Exception() << "no executable image located for process";

    Elf_Addr r_debug_addr = findRDebugAddr();
    isStatic = (r_debug_addr == 0 || r_debug_addr == (Elf_Addr)-1);
    if (isStatic)
        addElfObject(execImage, 0);
    else
        loadSharedObjects(r_debug_addr);

    td_err_e the;
    the = td_ta_new(this, &agent);
    if (the != TD_OK) {
        agent = 0;
        if (verbose && the != TD_NOLIBTHREAD)
            *debug << "failed to load thread agent: " << the << std::endl;
    }

}

DwarfInfo *
Process::getDwarf(std::shared_ptr<ElfObject> elf, bool debug)
{
    if (debug)
        elf = ElfObject::getDebug(elf);

    auto &info = dwarf[elf];
    if (info == 0)
        info = new DwarfInfo(elf);
    return info;
}

void
Process::processAUXV(const void *datap, size_t len)
{
    const Elf_auxv_t *aux = (const Elf_auxv_t *)datap;
    const Elf_auxv_t *eaux = aux + len / sizeof *aux;
    for (; aux < eaux; aux++) {
        Elf_Addr hdr = aux->a_un.a_val;
        switch (aux->a_type) {
            case AT_ENTRY: {
                // this provides a reference for relocating the executable when
                // compared to the entrypoint there.
                entry = hdr;
                break;
            }
            case AT_SYSINFO: {
                sysent = aux->a_un.a_val;
                break;
            }
            case AT_SYSINFO_EHDR: {
                size_t dsosize = getpagesize() * 2; // XXXX: page size is not enough. What is?
                vdso = new char[dsosize];
                // read as much of the header as we can.
                dsosize = io->read(hdr, dsosize, vdso);
                try {
                    auto elf = std::make_shared<ElfObject>(std::make_shared<MemReader>(vdso, dsosize));
                    addElfObject(elf, hdr - elf->getBase());
                    if (verbose >= 2)
                        *debug << "VDSO " << dsosize << " bytes loaded at " << elf.get() << "\n";

                }
                catch (...) {
                }
                break;
            }
#ifdef AT_EXECFN
            case AT_EXECFN:
                auto exeName = io->readString(hdr);
                if (verbose >= 2)
                    *debug << "filename from auxv: " << exeName << "\n";
                if (!execImage) {
                    execImage = std::make_shared<ElfObject>(exeName);
                    if (!entry)
                       entry = execImage->getElfHeader().e_entry;
                }

                break;
#endif
        }
    }
}

std::ostream &
Process::dumpStackJSON(std::ostream &os, const ThreadStack &thread)
{


    os << "{ \"ti_tid\": " << thread.info.ti_tid
        << ", \"ti_type\": " << thread.info.ti_type
        << ", \"stack\": [ ";

    const char *frameSep = "";
    for (auto frameI = thread.stack.begin(); frameI != thread.stack.end(); ++frameI) {
        auto frame = *frameI;
        Elf_Addr objIp = 0;
        std::shared_ptr<ElfObject> obj;
        Elf_Sym sym;
        std::string fileName;
        std::string symName = "unknown";
        if (frame->ip == sysent) {
            symName = "(syscall)";
        } else {
            Elf_Off reloc;
            obj = findObject(frame->ip, &reloc);
            if (obj) {
               fileName = obj->io->describe();
               objIp = frame->ip - reloc;
               obj->findSymbolByAddress(objIp, STT_FUNC, sym, symName);
            }
        }

        os << frameSep << "{ \"ip\": " << intptr_t(frame->ip);

        frameSep = ", ";

        if (symName != "")
            os << ", \"function\": \"" << symName << "\"";

        if (obj) {
            os << ", \"off\": " << intptr_t(objIp) - sym.st_value;
            os << ", \"file\": " << "\"" << fileName << "\"";
            auto di = getDwarf(obj);
            if (di) {
                auto src = di->sourceFromAddr(objIp - 1);
                for (auto ent = src.begin(); ent != src.end(); ++ent)
                    os
                        << ", \"source\": \"" << ent->first << "\""
                        << ", \"line\": " << ent->second;
            }
        }
        os << " }";
        frameSep = ", ";
    }
    return os << " ] }";
}

DwarfEntry *
findEntryForFunc(Elf_Addr address, DwarfEntry *entry)
{
   switch (entry->type->tag) {
      case DW_TAG_subprogram: {
         const DwarfAttribute *lowAttr = entry->attrForName(DW_AT_low_pc);
         const DwarfAttribute *highAttr =entry->attrForName(DW_AT_high_pc);
         if (lowAttr && highAttr) {
            Elf_Addr start, end;
            switch (lowAttr->spec->form) {
               case DW_FORM_addr:
                  start = lowAttr->value.addr;
                  break;
               default:
                  abort();
                  break;
            }
            switch (highAttr->spec->form) {
               case DW_FORM_addr:
                  end = highAttr->value.addr;
                  break;
               case DW_FORM_data1:
               case DW_FORM_data2:
               case DW_FORM_data4:
               case DW_FORM_data8:
               case DW_FORM_udata:
                  end = start + highAttr->value.sdata;
                  break;
               default:
                  abort();

            }
            if (start <= address && end > address)
               return entry;
         }
         break;
      }

      default:
         for (auto &child : entry->children) {
            auto descendent = findEntryForFunc(address, child.second);
            if (descendent)
               return descendent;
         }
         break;
   }
   return nullptr;
}

struct ArgPrint {
    const Process &p;
    const struct StackFrame *frame;
    ArgPrint(const Process &p_, const StackFrame *frame_) : p(p_), frame(frame_) {}
};

std::string
typeName(const DwarfEntry *type)
{
    if (type == 0) {
        return "void";
    }
    std::string name = type->name();
    if (name != "") {
        return name;
    }
    const DwarfEntry *base = type->referencedEntry(DW_AT_type);
    std::string s, sep;
    switch (type->type->tag) {
        case DW_TAG_pointer_type:
            return typeName(base) + " *";
        case DW_TAG_const_type:
            return typeName(base) + " const";
        case DW_TAG_volatile_type:
            return typeName(base) + " volatile";
        case DW_TAG_subroutine_type:
            s = typeName(base) + "(";
            sep = "";
            for (auto &arg : type->children) {
                if (arg.second->type->tag != DW_TAG_formal_parameter)
                    continue;
                s += sep;
                s += typeName(arg.second->referencedEntry(DW_AT_type));
                sep = ", ";
            }
            s += ")";
            return s;
        case DW_TAG_reference_type:
            return typeName(base) + "&";
        default: {
            std::ostringstream os;
            os << "(unhandled tag " << type->type->tag << ")";
            return os.str();
        }

    }
}

std::ostream &
operator << (std::ostream &os, const ArgPrint &ap)
{
    const char *sep = "";
    for (auto &childEnt : ap.frame->function->children) {
        const DwarfEntry *child = childEnt.second;
        switch (child->type->tag) {
            case DW_TAG_formal_parameter: {
                auto name = child->name();
                const DwarfEntry *type = child->referencedEntry(DW_AT_type);
                Elf_Addr addr = 0;
                os << sep << name;
                if (type) {
                    os << "[" << typeName(type) << "]";
                    const DwarfAttribute *locationA = child->attrForName(DW_AT_location);
                    if (locationA) {
                        DwarfExpressionStack fbstack;
                        addr = dwarfEvalExpr(ap.p, locationA, ap.frame, &fbstack);
                        IOFlagSave _(os);
                        os << "=" << std::hex << addr;
                        if (fbstack.isReg)
                           os << "{in register " << fbstack.inReg << "}";
                    }
                }
                sep = ", ";
                break;
            }
            default:
                break;
        }
    }
    return os;
}

std::ostream &
Process::dumpStackText(std::ostream &os, const ThreadStack &thread, const PstackOptions &options)
{
    os << "thread: " << (void *)thread.info.ti_tid << ", lwp: " << thread.info.ti_lid << ", type: " << thread.info.ti_type << "\n";
    for (auto frame : thread.stack) {

        os << "    ";
        if (verbose) {
              IOFlagSave _(os);
              os << "[ip=" << std::hex << std::setw(ELF_BITS/4) << std::setfill('0') << frame->ip
              << ", cfa=" << std::hex << std::setw(ELF_BITS/4) << std::setfill('0') << frame->cfa
              << "] ";
        }

        Elf_Sym sym;
        std::string fileName = "unknown file";
        std::string symName;

        Elf_Off reloc;
        auto obj = findObject(frame->ip, &reloc);
        if (obj) {
            fileName = obj->io->describe();
            Elf_Addr objIp = frame->ip - reloc;

            DwarfInfo *dwarf = getDwarf(obj, true);
            DwarfEntry *de = 0;
            bool haveDwarf = false;

            std::shared_ptr<DwarfUnit> dwarfUnit;
            for (const auto &rangeset : dwarf->ranges()) {
                for (const auto range : rangeset.ranges) {
                    if (objIp >= range.start && objIp <= range.start + range.length) {
                        auto dwarfUnit = dwarf->getUnit(rangeset.debugInfoOffset);
                        // find the DIE for this function
                        for (auto it : dwarfUnit->entries) {
                            de = findEntryForFunc(objIp - 1, it.second);
                            if (de) {
                                symName = de->name();
                                if (symName == "") {
                                   obj->findSymbolByAddress(objIp - 1, STT_FUNC, sym, symName);
                                   symName += "[nodwarfname]";
                                }
                                frame->function = de;
                                frame->dwarf = dwarf; // hold on to 'de'
                                os << symName << "+" << objIp - de->attrForName(DW_AT_low_pc)->value.udata << "(";
                                if (options(PstackOptions::doargs)) {
                                    os << ArgPrint(*this, frame);
                                }
                                os << ")";
                                haveDwarf = true;
                                break;
                            }
                        }
                        break;
                    }
                }
            }

            if (!haveDwarf) {
                if (frame->ip == sysent) {
                    symName = "(syscall)";
                } else {
                    try {
                        obj->findSymbolByAddress(objIp - 1, STT_FUNC, sym, symName);
                    } catch (...) {
                        std::ostringstream str;
                        str << "unknown";
                        if (dwarfUnit)
                            str << "(u)";

                        str << "@" << std::hex << frame->ip;
                        symName = str.str();
                    }
                    os << symName << "+" << objIp - sym.st_value << "()*";
                }
            }
            os << " in " << fileName;
            if (!options(PstackOptions::nosrc) && dwarf) {
                auto source = dwarf->sourceFromAddr(objIp - 1);
                for (auto ent = source.begin(); ent != source.end(); ++ent) {
                    os << " at ";
                    os << ent->first->directory << "/" << ent->first->name << ":" << std::dec << ent->second;
                }
            }
        } else {
            os << "no information for frame";
        }
        os << "\n";
    }
    return os;
}

void
Process::addElfObject(std::shared_ptr<ElfObject> obj, Elf_Addr load)
{
    objects.push_back(LoadedObject(load, obj));

    if (verbose >= 2) {
        IOFlagSave _(*debug);
        *debug
            << "object " << obj->io->describe()
            << " loaded at address " << std::hex << load
            << ", base=" << obj->getBase() << std::endl;
    }
}

/*
 * Grovel through the rtld's internals to find any shared libraries.
 */
void
Process::loadSharedObjects(Elf_Addr rdebugAddr)
{

    struct r_debug rDebug;
    io->readObj(rdebugAddr, &rDebug);

    /* Iterate over the r_debug structure's entries, loading libraries */
    struct link_map map;
    for (Elf_Addr mapAddr = (Elf_Addr)rDebug.r_map; mapAddr; mapAddr = (Elf_Addr)map.l_next) {
        io->readObj(mapAddr, &map);
        // first one's the executable itself.
        if (mapAddr == Elf_Addr(rDebug.r_map)) {
            assert(map.l_addr == entry - execImage->getElfHeader().e_entry);
            addElfObject(execImage, map.l_addr);
            continue;
        }
        /* Read the path to the file */
        if (map.l_name == 0) {
            IOFlagSave _(*debug);
            *debug << "warning: no name for object loaded at " << std::hex << map.l_addr << "\n";
            continue;
        }
        std::string path = io->readString(Elf_Off(map.l_name));
        if (path == "") {
            // XXX: dunno why this is.
            path = execImage->getInterpreter();
        }

        std::string startPath = path;
        for (auto it = pathReplacements.begin(); it != pathReplacements.end(); ++it) {
            size_t found = path.find(it->first);
            if (found != std::string::npos)
                path.replace(found, it->first.size(), it->second);
        }
        if (verbose && path != startPath)
            *debug << "replaced " << startPath << " with " << path << std::endl;

        try {
            addElfObject(std::make_shared<ElfObject>(path), Elf_Addr(map.l_addr));
        }
        catch (const std::exception &e) {
            std::clog << "warning: can't load text for '" << path << "' at " <<
            (void *)mapAddr << "/" << (void *)map.l_addr << ": " << e.what() << "\n";
            continue;
        }
    }
}

Elf_Addr
Process::findRDebugAddr()
{
    // Find DT_DEBUG in the process's dynamic section.
    auto &segments = execImage->getSegments();
    for (auto segment = segments.begin(); segment != segments.end(); ++segment) {
        if (segment->p_type != PT_DYNAMIC)
            continue;
        Elf_Off reloc = entry - execImage->getElfHeader().e_entry;
        // the dynamic section is in the executable, but the process A/S contains
        // the modified version.
        for (Elf_Addr dynOff = 0; dynOff < segment->p_filesz; dynOff += sizeof(Elf_Dyn)) {
            Elf_Dyn dyn;
            execImage->io->readObj(segment->p_offset + dynOff, &dyn);
            if (dyn.d_tag == DT_DEBUG) {
                // Now, we read this from the _process_ AS, not the executable - the
                // in-memory one is changed by the linker.
                io->readObj(segment->p_vaddr + dynOff + reloc, &dyn);
                return dyn.d_un.d_ptr;
            }
        }
    }
    return 0;
}

std::shared_ptr<ElfObject>
Process::findObject(Elf_Addr addr, Elf_Off *reloc) const
{
    for (auto i = objects.begin(); i != objects.end(); ++i) {
        auto &segments = i->object->getSegments();
        for (auto phdr = segments.begin(); phdr != segments.end(); ++ phdr) {
            Elf_Off addrReloc = addr - i->reloc;
            if (addrReloc >= phdr->p_vaddr && addrReloc < phdr->p_vaddr + phdr->p_memsz) {
                *reloc = i->reloc;
                return i->object;
            }
        }
    }
    return 0;
}

Elf_Addr
Process::findNamedSymbol(const char *objectName, const char *symbolName) const
{
    if (isStatic) // static exe: ignore object name.
        objectName = 0;
    for (auto i = objects.begin(); i != objects.end(); ++i) {
        auto obj = i->object;
        if (objectName != 0) {
            auto objname = obj->getName();
            auto p = objname.rfind('/');
            if (p != std::string::npos)
                objname = objname.substr(p + 1, std::string::npos);
            if (objname != std::string(objectName))
                continue;
        }
        Elf_Sym sym;
        if (obj->findSymbolByName(symbolName, sym))
            return sym.st_value + i->reloc;
        if (objectName)
            break;
    }
    Exception e;
    e << "symbol " << symbolName << " not found";
    if (objectName)
        e << " in " << objectName;
    throw e;
}

Process::~Process()
{
    td_ta_delete(agent);
    for (auto i = dwarf.begin(); i != dwarf.end(); ++i)
        delete i->second;
    delete[] vdso;
}

void
ThreadStack::unwind(Process &p, CoreRegisters &regs)
{
    stack.clear();
    try {
        auto prevFrame = new StackFrame();

        // Set up the first frame using the machine context registers
        prevFrame->ip = REG(regs, ip);
        prevFrame->setCoreRegs(regs);

        StackFrame *frame;
        for (size_t frameCount = 0; frameCount < gMaxFrames; frameCount++, prevFrame = frame) {
            stack.push_back(prevFrame);
            frame = prevFrame->unwind(p);
            if (!frame)
                break;
        }
    }
    catch (const std::exception &ex) {
        std::clog << "warning: exception unwinding stack: " << ex.what() << std::endl;
    }
}
