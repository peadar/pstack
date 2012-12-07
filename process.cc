#include <set>
#include <cassert>
#include <limits>
#include <limits.h>
#include <iostream>
#include <link.h>
extern "C" {
#include "proc_service.h"
}
#include "procinfo.h"
#include "dwarf.h"
#include "dump.h"

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

static int gFrameArgs = 6;		/* number of arguments to print */
static size_t gMaxFrames = 1024;		/* max number of frames to read */


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
        AUXV(AT_RANDOM)
        AUXV(AT_EXECFN)
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
    for (auto i : container)
        delete i;
}

Process::Process(std::shared_ptr<ElfObject> exec, std::shared_ptr<Reader> io_)
    : vdso(0)
    , io(std::shared_ptr<Reader>(new CacheReader(io_)))
    , execImage(exec)
    , entry(0)
    , isStatic(false)
    , sysent(0)
    , agent(0)
{
    abiPrefix = execImage->getABIPrefix();
}

std::shared_ptr<DwarfInfo>
Process::getDwarf(std::shared_ptr<ElfObject> elf)
{
    std::shared_ptr<DwarfInfo> &dwarf = this->dwarf[elf];
    if (dwarf == 0)
        dwarf.reset(new DwarfInfo(elf));
    return dwarf;
}

void
Process::load()
{
    td_err_e the;
    /* Attach any dynamically-linked libraries */

    /* Does this process look like it has shared libraries loaded? */
    Elf_Addr r_debug_addr = findRDebugAddr();

    isStatic = (r_debug_addr == 0 || r_debug_addr == (Elf_Addr)-1);
    if (isStatic)
        addElfObject(execImage, 0);
    else
        loadSharedObjects(r_debug_addr);
    the = td_ta_new(this, &agent);

    if (the != TD_OK) {
        agent = 0;
        if (debug)
            *debug << "failed to load thread agent: " << the << std::endl;
    }

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
                vdso = new char[getpagesize()];
                io->readObj(hdr, vdso, getpagesize());
                addElfObject(
                        std::shared_ptr<ElfObject>(new ElfObject(
                            std::shared_ptr<Reader>(new MemReader(vdso, getpagesize())))),
                            hdr);
                break;
            }

            case AT_EXECFN:
                auto exeName = io->readString(hdr);
                if (debug)
                    *debug << "filename from auxv: " << exeName << "\n";
                if (execImage == 0) {
                    FileReader *file = new FileReader(exeName);
                    execImage = std::shared_ptr<ElfObject>(
                            new ElfObject(std::shared_ptr<Reader>(file)));
                }
                break;
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
    for (auto frame : thread.stack) {
        Elf_Addr objIp = 0;
        std::shared_ptr<ElfObject> obj;
        int lineNo;
        Elf_Sym sym;
        std::string fileName;
        std::string symName = "unknown";
        if (frame->ip == sysent) {
            symName = "(syscall)";
        } else {
            try {
                auto i = findObject(frame->ip);
                fileName = i.second->io->describe();
                objIp = frame->ip - i.first;
                obj = i.second;
                obj->findSymbolByAddress(objIp, STT_FUNC, sym, symName);
            } catch (...) {
            }
        }

        os
            << frameSep << "{ \"ip\": " << intptr_t(frame->ip)
#ifdef i386
            << ", \"bp\": " << intptr_t(frame->bp)
#endif
            << ", \"unwind\": \"" << frame->unwindBy << "\"";

        frameSep = ", ";

        if (symName != "")
            os << ", \"function\": \"" << symName << "\"";

        os << ", \"args:\": [ ";
        const char *sep = "";
        for (auto &i : frame->args) {
            os << sep << i;
            sep = ", ";
        }
        os << " ]";
        if (obj != 0) {
            os << ", \"off\": " << intptr_t(objIp) - sym.st_value;
            os << ", \"file\": " << "\"" << fileName << "\"";
            auto di = getDwarf(obj);
            if (di)
                for (auto &ent : di->sourceFromAddr(objIp - 1))
                    os
                        << ", \"source\": \"" << ent.first << "\""
                        << ", \"line\": " << ent.second;
        }
        os << " }";
        frameSep = ", ";
    }
    return os << " ] }";
}

std::ostream &
Process::dumpStackText(std::ostream &os, const ThreadStack &thread)
{
    os << "thread: " << std::hex << thread.info.ti_tid << ", type: " << thread.info.ti_type << "\n";
    for (auto frame : thread.stack) {
        Elf_Addr objIp = 0;
        std::shared_ptr<ElfObject> obj = 0;
        int lineNo;
        Elf_Sym sym;
        std::string fileName = "unknown file";
        std::string symName = "unknown";
        if (frame->ip == sysent) {
            symName = "(syscall)";
        } else {
            try {
                auto i = findObject(frame->ip);
                fileName = i.second->io->describe();
                objIp = frame->ip - i.first;
                obj = i.second;
                obj->findSymbolByAddress(objIp, STT_FUNC, sym, symName);
            } catch (...) {
            }
        }

        os << "    " << symName << "(";
        const char *sep = "";
        for (auto &i : frame->args) {
            os << sep << "0x" << std::hex << i;
            sep = ", ";
        }
        os << ")";

        if (obj != 0) {
            os << " in " << fileName;
            auto di = getDwarf(obj);
            if (di) {
                for (auto &ent : di->sourceFromAddr(objIp - 1)) {
                    os << " at ";
                    if (debug)
                        os << "[" << ent.first->directory << "] ";
                    os << ent.first->name << ":" << std::dec << ent.second;
                }
            }
        }

        if (debug) {
            os
                << "\t(ip=0x" << std::hex << intptr_t(frame->ip)
#ifdef i386
                << ", bp=0x" << std::hex << intptr_t(frame->bp)
#endif
                << ", off=0x" << intptr_t(objIp) - sym.st_value;
            if (frame->unwindBy != "END")
                os << ", unwind by: " << frame->unwindBy;
            os << ")";
        }
        os << "\n";
    }
}

void
Process::addElfObject(std::shared_ptr<ElfObject> obj, Elf_Addr load)
{
    objects[load] = obj;

    if (debug)
        *debug
            << "object " << obj->io->describe()
            << " loaded at address " << std::hex << load
            << ", base=" << obj->base << std::endl;
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
            assert(map.l_addr == entry - execImage->elfHeader.e_entry);
            addElfObject(execImage, map.l_addr);
            continue;
        }
        /* Read the path to the file */
        if (map.l_name == 0) {
            std::clog << "warning: no name for object loaded at " << std::hex << map.l_addr << "\n";
            continue;
        }
        std::string path = io->readString(Elf_Off(map.l_name));
        try {
            addElfObject(std::shared_ptr<ElfObject>(new ElfObject(
                std::shared_ptr<Reader>(new FileReader(path)))), Elf_Addr(map.l_addr));
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
    auto dynamic = execImage->dynamic;
    if (dynamic == 0)
        return 0;

    Elf_Off reloc = entry - execImage->elfHeader.e_entry;

    // the dynamic section is in the executable, but the process A/S contains
    // the modified version.
    for (Elf_Addr dynOff = 0; dynOff < dynamic->p_filesz; dynOff += sizeof(Elf_Dyn)) {
        Elf_Dyn dyn;
        execImage->io->readObj(dynamic->p_offset + dynOff, &dyn);
        if (dyn.d_tag == DT_DEBUG) {
            // Now, we read this from the _process_ AS, not the executable - the
            // in-memory one is changed by the linker.
            io->readObj(dynamic->p_vaddr + dynOff + reloc, &dyn);
            return dyn.d_un.d_ptr;
        }
    }
    return 0;
}


std::pair<Elf_Off, std::shared_ptr<ElfObject>>
Process::findObject(Elf_Addr addr) const
{
    for (auto &i : objects)
        for (auto &phdr : i.second->programHeaders) {
            Elf_Off reloc = addr - i.first;
            if (reloc >= phdr->p_vaddr && reloc < phdr->p_vaddr + phdr->p_memsz)
                return i;
        }
    throw Exception() << "no loaded object at address 0x" << std::hex << addr;
}

Elf_Addr
Process::findNamedSymbol(const char *objectName, const char *symbolName) const
{
    if (isStatic) // static exe: ignore object name.
        objectName = 0;
    for (auto &i : objects) {
        auto obj = i.second;
        if (objectName != 0) {
            auto objname = obj->io->describe();
            auto p = objname.rfind('/');
            if (p != std::string::npos)
                objname = objname.substr(p + 1, std::string::npos);
            if (objname != std::string(objectName))
                continue;
        }
        Elf_Sym sym;
        if (obj->findSymbolByName(symbolName, sym))
            return sym.st_value + i.first;
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
    delete[] vdso;
    td_ta_delete(agent);
}

void
ThreadStack::unwind(Process &p, CoreRegisters &regs)
{
    stack.clear();
    /* Put a bound on the number of iterations. */
    for (size_t frameCount = 0; frameCount < gMaxFrames; frameCount++) {
        Elf_Addr ip;
        StackFrame *frame = new StackFrame(ip = REG(regs, ip),
#ifdef __PPC
                0
#else
                REG(regs, bp)
#endif
                );
        stack.push_back(frame);

        DwarfRegisters dr;
        dwarfPtToDwarf(&dr, &regs);

        // try dwarf first...
        if ((ip = dwarfUnwind(p, &dr, ip)) != 0) {
            frame->unwindBy = "dwarf";
            dwarfDwarfToPt(&regs, &dr);
        } else {
#ifndef __PPC
            try {
                for (int i = 0; i < gFrameArgs; i++) {
                    Elf_Word arg;
                    p.io->readObj(Elf_Addr(REG(regs, bp)) + sizeof(Elf_Word) * 2 + i * sizeof(Elf_Word), &arg);
                    frame->args.push_back(arg);
                }
            }
            catch (...) {
                // not fatal if we can't read all the args.
            }
#endif
            frame->unwindBy = "END  ";
#ifdef __PPC
            break;
#else

            /* Read the next frame */
            try {
                // Call site's instruction pointer is just above the frame pointer
                p.io->readObj(Elf_Addr(REG(regs, bp)) + sizeof(REG(regs, bp)), &ip);
                REG(regs, ip) = ip;
                if (ip == 0) // XXX: if no return instruction, break out.
                        break;
                // Read new frame pointer from stack.
                p.io->readObj(Elf_Addr(REG(regs, bp)), &REG(regs, bp));
                if (Elf_Addr(REG(regs, bp)) <= frame->bp)
                    break;
            }
            catch (...) {
                break;
            }
            frame->unwindBy = "stdc  ";
#endif
        }
    }
}
