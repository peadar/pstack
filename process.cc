#include <set>
#include <cassert>
#include <limits>
#include <limits.h>
#include <iostream>
#include <link.h>
#include <unistd.h>
#include <libpstack/ps_callback.h>
#include <libpstack/proc.h>
#include <libpstack/dwarf.h>
#include <libpstack/dwarfproc.h>
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

static std::string auxv_name(Elf_Word val)
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
        if (debug)
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
        if (debug)
            *debug << "auxv: " << auxv_name(aux->a_type) << "= " << (void *)hdr << "\n";
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
                    if (debug)
                        *debug << "VDSO " << dsosize << " bytes loaded at " << elf.get() << "\n";

                }
                catch (...) {
                }
                break;
            }
#ifdef AT_EXECFN
            case AT_EXECFN:
                auto exeName = io->readString(hdr);
                if (debug)
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
            try {
                auto i = findObject(frame->ip);
                fileName = i.object->io->describe();
                objIp = frame->ip - i.reloc;
                obj = i.object;
                obj->findSymbolByAddress(objIp, STT_FUNC, sym, symName);
            } catch (...) {
            }
        }

        os
            << frameSep << "{ \"ip\": " << intptr_t(frame->ip)
            << ", \"unwind\": \"" << frame->unwindBy << "\"";

        frameSep = ", ";

        if (symName != "")
            os << ", \"function\": \"" << symName << "\"";

        os << ", \"args:\": [ ";
        const char *sep = "";
        for (auto i = frame->args.begin(); i != frame->args.end(); ++i) {
            os << sep << *i;
            sep = ", ";
        }
        os << " ]";
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

std::shared_ptr<DwarfEntry>
findEntryForFunc(Elf_Addr address, std::shared_ptr<DwarfEntry> &entry)
{
   switch (entry->type->tag) {
      case DW_TAG_subprogram: {
         const DwarfAttribute *lowAttr, *highAttr;
         if (entry->attrForName(DW_AT_low_pc, &lowAttr) && entry->attrForName(DW_AT_high_pc, &highAttr)) {
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

void
Process::printArgs(const DwarfEntry *function, const StackFrame *frame)
{
   for (auto &childEnt : function->children) {
      const std::shared_ptr<DwarfEntry> child = childEnt.second;
      switch (child->type->tag) {
         case DW_TAG_formal_parameter:
            const DwarfAttribute *locationA;
            if (child->attrForName(DW_AT_location, &locationA)) {
               pause();
            }
            break;
         default:
            break;
      }
   }
}

std::ostream &
Process::dumpStackText(std::ostream &os, const ThreadStack &thread, const PstackOptions &options)
{
    os << "thread: " << (void *)thread.info.ti_tid << ", lwp: " << thread.info.ti_lid << ", type: " << thread.info.ti_type << "\n";
    for (auto frame : thread.stack) {
        Elf_Addr objIp = 0;
        std::shared_ptr<ElfObject> obj;
        Elf_Sym sym;
        std::string fileName = "unknown file";
        std::string symName = "unknown";
        if (frame->ip == sysent) {
            symName = "(syscall)";
        } else {
            try {
                auto i = findObject(frame->ip);
                fileName = i.object->io->describe();
                objIp = frame->ip - i.reloc;
                obj = i.object;
                obj->findSymbolByAddress(objIp, STT_FUNC, sym, symName);

            } catch (...) {
                std::ostringstream str;
                str << "unknown@" << std::hex << frame->ip;
                symName = str.str();
            }
        }

        auto dwarf = getDwarf(obj, true);
        std::shared_ptr<DwarfEntry> de;
        if (dwarf) {
            for (const auto &rangeset : dwarf->ranges()) {
                for (const auto range : rangeset.ranges) {
                    auto tu = dwarf->units()[rangeset.debugInfoOffset];
                    if (objIp >= range.start && objIp <= range.start + range.length) {
                        // find the DIE for this function
                        for (auto it : tu->entries) {
                            de = findEntryForFunc(objIp, it.second);
                            if (de)
                                break;
                        }
                        break;
                    }
                }
            }
        }
        const DwarfAttribute *dwarfNamea;
        if (de && de->attrForName(DW_AT_name, &dwarfNamea)) {
            std::string dwarfName = dwarfNamea->value.string;
            if (dwarfName != symName) {
                if (debug)
                    *debug << "override name " << symName << "\n";
                symName = dwarfName;
            }
        }

        os << "    " << symName << "(";
        if (de) {
           printArgs(de.get(), frame);
        }
        os << ")";

        if (obj) {
            os << " in " << fileName;
            if (!options(PstackOptions::nosrc)) {
                auto di = getDwarf(obj);
                if (di) {
                    auto source = di->sourceFromAddr(objIp - 1);
                    for (auto ent = source.begin(); ent != source.end(); ++ent) {
                        os << " at ";
                        if (debug)
                            os << "[" << ent->first->directory << "] ";
                        os << ent->first->name << ":" << std::dec << ent->second;
                    }
                }
            }
        }

        if (debug) {
            os
                << "\t(ip=0x" << std::hex << intptr_t(frame->ip)
                << ", objip=0x" << std::hex << objIp
                << ", symval=0x" << std::hex << sym.st_value
                << ", off=0x" << std::hex << intptr_t(objIp) - sym.st_value;
            if (strcmp(frame->unwindBy, "END") != 0)
                os << ", unwind by: " << frame->unwindBy;
            os << ")";
        }
        os << "\n";
    }
    return os;
}

void
Process::addElfObject(std::shared_ptr<ElfObject> obj, Elf_Addr load)
{
    objects.push_back(LoadedObject(load, obj));

    if (debug)
        *debug
            << "object " << obj->io->describe()
            << " loaded at address " << std::hex << load
            << ", base=" << obj->getBase() << std::endl;
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
            std::clog << "warning: no name for object loaded at " << std::hex << map.l_addr << "\n";
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
        if (debug && path != startPath)
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


Process::LoadedObject
Process::findObject(Elf_Addr addr) const
{
    for (auto i = objects.begin(); i != objects.end(); ++i) {
        auto &segments = i->object->getSegments();
        for (auto phdr = segments.begin(); phdr != segments.end(); ++ phdr) {
            Elf_Off reloc = addr - i->reloc;
            if (reloc >= phdr->p_vaddr && reloc < phdr->p_vaddr + phdr->p_memsz)
                return *i;
        }
    }
    throw Exception() << "no loaded object at address 0x" << std::hex << addr;
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
        /* Put a bound on the number of iterations. */
        Elf_Addr ip = REG(regs, ip);
        DwarfRegisters dr;
        dwarfPtToDwarf(&dr, &regs);
        for (size_t frameCount = 0; frameCount < gMaxFrames; frameCount++) {
            StackFrame *frame = new StackFrame(ip);
            stack.push_back(frame);
            if (!dwarfUnwind(p, &dr, ip)) {
                frame->unwindBy = "end";
#ifdef __i386__

#define R_EBP 5
#define R_EIP 8

                // Read the instruction pointer from just below the base pointer,
                // and the new base pointer, from the existing one.
                uint32_t newBp;
                uint32_t newIp;
                try {
                   p.io->readObj((dr.reg[R_EBP] + 4) & 0xffffffff, &newIp);
                   p.io->readObj(dr.reg[R_EBP] & 0xffffffff, &newBp);
                   dr.reg[R_EBP] = newBp;
                   dr.reg[R_EIP] = newIp;
                   ip = newIp;
                   if (newIp) {
                      frame->unwindBy = "arch";
                   } else {
#endif
                      break;
#ifdef __i386__
                   }
                } catch (...) {
                   break;
                }
#endif
            } else {
               frame->unwindBy = "dwarf";
            }
        }
    }
    catch (const std::exception &ex) {
        std::clog << "exception unwinding stack: " << ex.what() << std::endl;
    }
}
