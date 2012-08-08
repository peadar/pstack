/*
 * Copyright (c) 2002, 2004 Peter Edwards
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Given a process ID or core file, try to get a backtrace of every thread in
 * that process.
 */

#include <sys/param.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <sys/ptrace.h>

#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <iostream>
#include <set>

/*
 * ps_prochandle should be declared before including thread_db.h to
 * avoid warnings
 */

extern "C" {
#include <thread_db.h>
}
#ifdef __FreeBSD__
#include <proc_service.h>
typedef struct regs ptrace_regs;

#ifdef __i386__
#define REG(regs, reg) (regs.r_e##reg)
#endif

#ifdef __amd64__
#define REG(regs, reg) (regs.r_r##reg)
#endif

#endif

#ifdef __linux__
typedef struct user_regs_struct  elf_regs;
#ifdef __i386__
#define REG(regs, reg) ((regs).e##reg)
#else
#define REG(regs, reg) ((regs).r##reg)
#endif
#else
#error "not linux?"
#endif

#include "elfinfo.h"
#include "procinfo.h"
#include "dwarf.h"

/* Callback data for procRegsFromNote */
struct RegnoteInfo {
    const Process *proc;
    lwpid_t pid;
    CoreRegisters *reg;
};

/*
 * Command-line flags
 */
static int gFrameArgs = 6;		/* number of arguments to print */
static size_t gMaxFrames = 1024;		/* max number of frames to read */
static int gShowObjectNames = 0;	/* show names of objects for each IP */
int gVerbose = 0;
static int gWantDwarf = 0;

/* Prototypes */
static int usage(void);
static int procThreadIterate(const td_thrhandle_t *thr, void *p);

static enum NoteIter procRegsFromNote(void *cookie, const char *name, u_int32_t type, const void *data, size_t len);

template <typename T> static void
delall(T &container)
{
    for (auto i : container)
        delete i;
}


static void
dwarf(struct ElfObject *obj)
{
    DwarfInfo dwarf(obj);
    dwarfDump(stdout, 0, &dwarf);
}

void
pstack(Process &proc)
{
    proc.load();
    std::set<pid_t> lwps;

    td_ta_thr_iter(
        proc.agent,
        [] (const td_thrhandle_t *thr, void *v) -> int {
            auto lwps = static_cast<std::set<pid_t> *>(v);
            if (td_thr_dbsuspend(thr) == TD_NOCAPAB) {
                td_thrinfo_t info;
                td_thr_get_info(thr, &info);
                lwps->insert(info.ti_lid);
            }
            return 0;
        },
        &lwps,
        TD_THR_ANY_STATE,
        TD_THR_LOWEST_PRIORITY,
        TD_SIGNO_MASK,
        TD_THR_ANY_USER_FLAGS);


    for (auto lwp : lwps)
        ps_lstop(&proc, lwp);

    std::list<ThreadStack> threadStacks;

    // get its back trace.

    td_ta_thr_iter(
        proc.agent,
        [] (const td_thrhandle_t *thr, void *v) -> int {
            auto stacks = static_cast<std::list<ThreadStack> *>(v);
            stacks->push_back(ThreadStack(t));
            stacks->back().unwind(proc);
        },
        &threadStacks,
        TD_THR_ANY_STATE,
        TD_THR_LOWEST_PRIORITY,
        TD_SIGNO_MASK,
        TD_THR_ANY_USER_FLAGS);
    for (auto t : threads) {
    }

    for (auto s : threadStacks)
        proc.dumpStack(stdout, 0, s);

    // resume each thread
    for (auto handle = threads.begin(); handle != threads.end(); ++handle)
        td_thr_dbresume(*handle);


    // resume each lwp
    for (auto lwp : lwps)
        ps_lcontinue(&proc, lwp);
}

int
main(int argc, char **argv)
{
    char *cp;
    int error, i, c;
    pid_t pid;
    std::string execFile, coreFile;


    while ((c = getopt(argc, argv, "a:d:D:e:f:hloOv")) != -1) {
        switch (c) {
        case 'a':
            gFrameArgs = atoi(optarg);
            break;

        case 'l':
            gWantDwarf = 1;
            break;

        case 'D': {
            FileReader r(optarg);
            ElfObject dumpObj(r);
            dwarf(&dumpObj);
            break;
        }

        case 'd': {
            /* Undocumented option to dump image contents */
            FileReader r(optarg);
            ElfObject dumpobj(r);
            std::cout << dumpobj;
            return 0;
        }

        case 'e':
            execFile = optarg;
            break;

        case 'f':
            gMaxFrames = strtoul(optarg, &cp, 0);
            if (gMaxFrames == 0 || *cp != '\0')
                    errx(EX_USAGE, "invalid stack frame count");
            break;

        case 'h':
            usage();
            return (0);

        case 'o':
            gShowObjectNames = 1;
            break;

        case 'O':
            gShowObjectNames = 2;
            break;

        case 'v':
            gVerbose++;
            gShowObjectNames++;
            break;

        default:
            return (usage());

        }
    }
    if (optind == argc)
        return (usage());

    for (error = 0, i = optind; i < argc; i++) {
        pid = atoi(argv[i]);
        FileReader execData(execFile);
        if (pid == 0 || (kill(pid, 0) == -1 && errno == ESRCH)) {
            FileReader coreFile(argv[i]);
            CoreProcess proc(execData, coreFile);
            pstack(proc);
        } else {
            LiveProcess proc(execData, pid);
            pstack(proc);
        }
    }
    return (error);
}

static int
usage(void)
{
    fprintf(stderr, "usage: pstack\n\t"
        "[-hoOt] "
        "[-a arg count] "
        "[-e executable] "
        "[-f max frame count] "
        "[-l]"
        "pid|core ...\n"
        "\tor\n"
        "\t<-d ELF-file> [-s snaplen]\n");
    return (EX_USAGE);
}

static enum NoteIter
procAddVDSO(void *cookie, const char *name, u_int32_t type, const void *datap, size_t len)
{
    if (type == NT_AUXV) {
        static_cast<Process *>(cookie)->addVDSOfromAuxV(datap, len);
        return NOTE_DONE;
    }
    return NOTE_CONTIN;
}

void
ps_prochandle::addVDSOfromAuxV(const void *datap, size_t len)
{
    const Elf_auxv_t *aux = (const Elf_auxv_t *)datap;
    const Elf_auxv_t *eaux = aux + len / sizeof *aux;
    Elf_Addr hdr = 0;
    while (aux < eaux)
        if (aux->a_type == AT_SYSINFO_EHDR) {
            hdr = aux->a_un.a_val;
            vdso = new char[getpagesize()];
            readObj(hdr, vdso, getpagesize());
            MemReader *r = new MemReader(vdso, getpagesize());
            readers.push_back(r);
            addElfObject(new ElfObject(*r), hdr);
            return;
        }
}

/*
 * Create a description of a process. Attempt to get:
 *	 A description of the executable object.
 *	 A description of any loaded objects from the run-time linker.
 *	 A stack trace for each thread we find, as well as the currently
 *	 running thread.
 */
CoreProcess::CoreProcess(Reader &exe, Reader &coreFile)
    : ps_prochandle(exe)
    , coreImage(coreFile)
{
}

ps_prochandle::ps_prochandle(Reader &exeData)
    : execImage(new ElfObject(exeData))
{
    abiPrefix = execImage->getABIPrefix();
    addElfObject(execImage, 0);
    execImage->load = execImage->base; // An executable is loaded at its own base address
}

void
CoreProcess::load()
{
#ifdef __linux__
    /* Find the linux-gate VDSO, and treat as an ELF file */
    coreImage.getNotes(procAddVDSO, this);
#endif
    Process::load();
}

void
LiveProcess::load()
{
#ifdef __linux__
    char path[PATH_MAX];
    snprintf(path, sizeof path, "/proc/%d/auxv", pid);
    int fd = open(path, O_RDONLY);
    if (fd == -1)
        throw 999;
    char buf[4096];
    ssize_t rc = ::read(fd, buf, sizeof buf);
    close(fd);
    if (rc == -1)
        throw 999;
    addVDSOfromAuxV(buf, rc);
#endif
    Process::load();
}

ThreadList::ThreadList(Process &p)
{
}

void
ps_prochandle::load()
{

    td_err_e the;
    /* Attach any dynamically-linked libraries */
    loadSharedObjects();
    the = td_ta_new(this, &agent);
    if (the != TD_OK)
        throw 999;
}


const Elf_Phdr *
ElfObject::findHeaderForAddress(Elf_Addr pa) const
{
    Elf_Addr va = addrProc2Obj(pa);
    for (auto hdr : programHeaders)
        if (hdr->p_vaddr <= va && hdr->p_vaddr + hdr->p_filesz > va && hdr->p_type == PT_LOAD)
            return hdr;
    return 0;
}

void
CoreProcess::read(off_t remoteAddr, size_t size, char *ptr) const
{
    size_t readLen = 0;
    /* Locate "remoteAddr" in the core file */
    while (size) {
        auto obj = &coreImage;
        auto hdr = obj->findHeaderForAddress(remoteAddr);
        if (hdr == 0)
            for (auto o : objectList) {
                hdr = o->findHeaderForAddress(remoteAddr);
                if (hdr) {
                    obj = o;
                    break;
                }
            }
        if (hdr == 0)
            throw 999;
        Elf_Addr addr = obj->addrProc2Obj(remoteAddr);
        size_t fragSize = MIN(hdr->p_vaddr + hdr->p_memsz - remoteAddr, size);
        obj->io.readObj(hdr->p_offset + addr - hdr->p_vaddr, ptr, fragSize);
        size -= fragSize;
        readLen += fragSize;
    }
}

LiveProcess::LiveProcess(Reader &ex, pid_t pid_)
    : ps_prochandle(ex)
    , pid(pid_)
{
    char buf[PATH_MAX];
    snprintf(buf, sizeof buf, "/proc/%d/mem", pid);
    procMem = fopen(buf, "r");
    if (procMem == 0)
        throw 999;
}

/*
 * Read data from the target's address space.
 */
void
LiveProcess::read(off_t remoteAddr, size_t size, char *ptr) const
{
    if (fseek(procMem, remoteAddr, SEEK_SET) == -1)
        throw 999;
    if (fread(ptr, size, 1, procMem) != 1)
        throw 999;

}

void
ThreadStack::unwind(Process &p)
{
    CoreRegisters regs;

    td_err_e the;
#ifdef __linux__ // XXX: looks wrong on linux, right on BSD
    the = td_thr_getgregs(handle, (elf_greg_t *) &regs);
#else
    the = td_thr_getgregs(handle, &regs);
#endif
    if (the != TD_OK)
        throw 999;

    stack.clear();
    /* Put a bound on the number of iterations. */
    for (size_t frameCount = 0; frameCount < gMaxFrames; frameCount++) {
        Elf_Addr ip;
        StackFrame *frame = new StackFrame(ip = REG(regs, ip), REG(regs, bp));
        stack.push_back(frame);

        DwarfRegisters dr;
        dwarfPtToDwarf(&dr, &regs);

        if (gWantDwarf && (ip = dwarfUnwind(p, &dr, ip)) != 0) {
            frame->unwindBy = "dwarf";
            dwarfDwarfToPt(&regs, &dr);
        } else {
            try {
                for (int i = 0; i < gFrameArgs; i++) {
                    Elf_Word arg;
                        p.readObj(REG(regs, bp) + sizeof(Elf_Word) * 2 + i * sizeof(Elf_Word), &arg);
                        frame->args.push_back(arg);
                    }
            }
            catch (...) {
                // not fatal if we can't read all the args.
            }
            frame->unwindBy = "END  ";
            /* Read the next frame */
            try {
                p.readObj(REG(regs, bp) + sizeof(REG(regs, bp)), &ip);
                REG(regs, ip) = ip;
                if (ip == 0) // XXX: if no return instruction, break out.
                        break;
                // Read new frame pointer from stack.
                p.readObj(REG(regs, bp), &REG(regs, bp));
                if ((uintmax_t)REG(regs, bp) <= frame->bp)
                    break;
            }
            catch (...) {
                break;
            }
            frame->unwindBy = "stdc  ";
        }
    }
}


/*
 * Print a stack trace of each stack in the process
 */
void
ps_prochandle::dumpStack(FILE *file, int indent, const ThreadStack &thread)
{
    struct ElfObject *obj;
    int lineNo;
    Elf_Sym sym;
    std::string fileName;
    const char *padding;
    std::string symName;

    padding = pad(indent);
    for (auto frame : thread.stack) {
        symName = fileName = "????????";
        Elf_Addr objIp;
        obj = findObject(frame->ip);

        if (obj != 0) {
            fileName = obj->io.describe();
            obj->findSymbolByAddress(obj->addrProc2Obj(frame->ip), STT_FUNC, sym, symName);
            objIp = obj->addrProc2Obj(frame->ip);
        } else {
            objIp = 0;
        }
        fprintf(file, "%s%p ", padding - 1, (void *)(intptr_t)frame->ip);
        if (gVerbose) { /* Show ebp for verbose */
#ifdef i386
            fprintf(file, "%p ", (void *)frame->bp);
#endif
            fprintf(file, "%s ", frame->unwindBy);
        }

        fprintf(file, "%s (", symName.c_str());
        if (frame->args.size()) {
            auto i = frame->args.begin();
            for (; i != frame->args.end(); ++i)
                fprintf(file, "%x, ", *i);
            fprintf(file, "%x", *i);
        }
        fprintf(file, ")");
        if (obj != 0) {
            printf(" + %p", (void *)((intptr_t)objIp - sym.st_value));
            if (gShowObjectNames)
                printf(" in %s", fileName.c_str());
            if (obj->dwarf && obj->dwarf->sourceFromAddr(objIp - 1, fileName, lineNo))
                printf(" (source %s:%d)", fileName.c_str(), lineNo);
        }
        printf("\n");
    }
    fprintf(file, "\n");
}

/*
 * Add ELF object description into process.
 */
void
ps_prochandle::addElfObject(struct ElfObject *obj, Elf_Addr load)
{
    obj->load = load;
    obj->base = (Elf_Addr)-1;

    for (auto hdr : obj->programHeaders)
        if (hdr->p_type == PT_LOAD && hdr->p_vaddr < obj->base)
            obj->base = hdr->p_vaddr;

    objectList.push_back(obj);

    if (gVerbose) {
        fprintf(stderr, "object %s loaded at address %p, base=%p\n",
            "XXX", (void *)obj->load, (void *)obj->base);
    }

    if (gWantDwarf) {
        DwarfInfo *di = obj->dwarf = new DwarfInfo(obj);
        if (gVerbose)
            fprintf(stderr, "unwind info: %s\n", 
                    di->ehFrame ? di->debugFrame ? "BOTH" : "EH" : di->debugFrame ? "DEBUG" : "NONE");
    } else {
        obj->dwarf = 0;
    }
}

/*
 * Grovel through the rtld's internals to find any shared libraries.
 */
void
ps_prochandle::loadSharedObjects()
{
    int maxpath;
    char prefixedPath[PATH_MAX + 1], *path;

    /* Does this process look like it has shared libraries loaded? */
    Elf_Addr r_debug_addr = findRDebugAddr();
    if (r_debug_addr == 0 || r_debug_addr == (Elf_Addr)-1)
        return;

    struct r_debug rDebug;
    readObj(r_debug_addr, &rDebug);
    if (abiPrefix != "") {
        path = prefixedPath + snprintf(prefixedPath, sizeof(prefixedPath), "%s", abiPrefix.c_str());
        maxpath = PATH_MAX - strlen(abiPrefix.c_str());
    } else {
        path = prefixedPath;
        maxpath = PATH_MAX;
    }

    /* Iterate over the r_debug structure's entries, loading libraries */
    struct link_map map;
    for (Elf_Addr mapAddr = (Elf_Addr)rDebug.r_map; mapAddr; mapAddr = (Elf_Addr)map.l_next) {
        readObj(mapAddr, &map);

        /* Read the path to the file */
        if (map.l_name == 0)
            continue;
        try {
            readObj((off_t)map.l_name, path, maxpath);
            if (abiPrefix != "" && access(prefixedPath, R_OK) == 0)
            path = prefixedPath;
            FileReader *f = new FileReader(path);
            readers.push_back(f);
            Elf_Addr lAddr = (Elf_Addr)map.l_addr;
            addElfObject(new ElfObject(*f), lAddr);
        }
        catch (...) {
            std::clog << "warning: can't load text at " << (void *)mapAddr << "\n";
            continue;
        }

    }
}

/*
 * Grab various bits of information from the run-time linker.
 */
Elf_Addr
ps_prochandle::findRDebugAddr()
{
    // Find DT_DEBUG in the process's dynamic section.
    if (execImage->dynamic == 0)
        return 0;

    for (Elf_Addr dynOff = 0; dynOff < execImage->dynamic->p_filesz; dynOff += sizeof(Elf_Dyn)) {
        Elf_Dyn dyn;
        execImage->io.readObj(execImage->dynamic->p_offset + dynOff, &dyn);
        if (dyn.d_tag == DT_DEBUG) {
            readObj(execImage->dynamic->p_vaddr + dynOff, &dyn);
            return dyn.d_un.d_ptr;
        }
    }
    return 0;
}

static const char PRSTATUS_NOTENAME[] = 
#if defined(__FreeBSD__)
            "FreeBSD"
#elif defined(__linux__)
            "CORE"
#endif
    ;

#ifdef NOTYET
static enum NoteIter procAddThreadsFromNotes(void *, const char *, u_int32_t, const void *, size_t);
static enum NoteIter
procAddThreadsFromNotes(void *cookie, const char *name, u_int32_t type,
    const void *data, size_t len)
{

    const prstatus_t *prstatus = (const prstatus_t *)data;
    Process *p = (Process *)cookie;
    if (strcmp(name, PRSTATUS_NOTENAME) == 0 && type == NT_PRSTATUS)
        p->addThread(new Thread(0, prstatus->pr_pid));
    return (NOTE_CONTIN);
}
#endif

static enum NoteIter
procRegsFromNote(void *cookie, const char *name, u_int32_t type,
    const void *data, size_t len)
{
    const prstatus_t *prstatus;
    struct RegnoteInfo *rni;

    prstatus = (const prstatus_t *)data;
    rni = (RegnoteInfo *)cookie;
    if (strcmp(name, PRSTATUS_NOTENAME) == 0 && type == NT_PRSTATUS && prstatus->pr_pid == rni->pid) {
        memcpy(rni->reg, (const DwarfRegisters *)&prstatus->pr_reg, sizeof(*rni->reg));
        return (NOTE_DONE);
    }
    return (NOTE_CONTIN);
}

int
CoreProcess::getRegs(lwpid_t pid, CoreRegisters *reg) const
{
    struct RegnoteInfo rni;
    rni.proc = this;
    rni.pid = pid;
    rni.reg = reg;
    return coreImage.getNotes(procRegsFromNote, &rni);
}

int
LiveProcess::getRegs(lwpid_t pid, CoreRegisters *reg) const
{
#ifdef __FreeBSD__
    int rc;
    rc = ptrace(PT_GETREGS, pid, (caddr_t)reg, 0);
    if (rc == -1)
        warn("failed to trace LWP %d", (int)pid);
    return (rc);
#endif
#ifdef __linux__
    return ptrace(__ptrace_request(PTRACE_GETREGS), pid, 0, reg) != -1 ? PS_OK : PS_ERR;
#endif
}


/*
 * Free any resources associated with a Process
 */
Process::~Process()
{
    delall(objectList);
    delete[] vdso;
}

#ifdef __linux__
#define THR_ID(t) ((intptr_t)(t)->th_unique)
#else
#define THR_ID(t) ((t)->th_tid)
#endif

static int
procThreadIterate(const td_thrhandle_t *thr, void *v)
{
    ThreadList *list = reinterpret_cast<ThreadList *>(v);
    list->push_back(thr);
    return (0);
}

/*
 * A very basic proc_service implementation.
 * Those functions that are not required for pstack abort().
 */

ps_err_e ps_lcontinue(const struct ps_prochandle *p, lwpid_t pid)
{
    try {
        p->resume(pid);
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

void
LiveProcess::resume(pid_t pid) const
{
    if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
        warn("failed to detach from process %d", pid);
}

void
CoreProcess::resume(pid_t) const
{
    // can't resume post-mortem debugger.
}

ps_err_e ps_lgetfpregs(struct ps_prochandle *p, lwpid_t pid, prfpregset_t *fpregsetp)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_lgetregs(struct ps_prochandle *p, lwpid_t pid, prgregset_t gregset)
{
    return (p->getRegs(pid, (CoreRegisters *)gregset) == 0 ? PS_OK : PS_ERR);
}

ps_err_e ps_lsetfpregs(struct ps_prochandle *p, lwpid_t pid, const prfpregset_t *fpregsetp)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_lsetregs(struct ps_prochandle *p, lwpid_t pid,
		const prgregset_t gregset)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_lstop(const struct ps_prochandle *p, lwpid_t lwpid)
{
    try {
        p->stop(lwpid);
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

void
CoreProcess::stop(lwpid_t pid) const
{
    // can't stop a dead process.
}

void
LiveProcess::stop(lwpid_t pid) const
{
    int status;
#ifdef __linux__
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0)
        throw 999;
    if (waitpid(pid, &status, 0) == -1)
        throw 999;
#endif
#ifdef __FreeBSD__
    if (ptrace(PT_ATTACH, pid, 0, 0) != 0)
        throw 999;
    /*
     * Wait for child to stop.
     * XXX: Due to an interaction between ptrace() and linux
     * thread semantics, the "normal" waitpid may fail. We
     * do our best to guess when this happens, and try again
     * with options |= WLINUXCLONE
     */
    if (waitpid(pid, &status, 0) == -1) {
#if !defined(MISC_39201_FIXED)
        if (errno != ECHILD || waitpid(pid, &status, WLINUXCLONE) == -1)
            warnx("(linux thread process detected: waiting with WLINUXCLONE)");
        else
#endif
            warn("can't wait for child: all bets " "are off");
    }
#endif
}

ps_err_e ps_pcontinue(const struct ps_prochandle *p)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_pdmodel(struct ps_prochandle *p, int *model)
{
    abort();
    return (PS_ERR);
}

ps_err_e
ps_pglobal_lookup(struct ps_prochandle *p, const char *ld_object_name,
	const char *ld_symbol_name, psaddr_t *ld_symbol_addr)
{
    for (auto obj : p->objectList) {
        if (ld_object_name != 0) {
            auto objname = obj->io.describe();
            auto p = objname.rfind('/');
            if (p != std::string::npos)
                objname = objname.substr(p + 1, std::string::npos);
            if (objname != std::string(ld_object_name))
                continue;
        }
        Elf_Sym sym;
        if (obj->findSymbolByName(ld_symbol_name, sym)) {
            *ld_symbol_addr = (psaddr_t)obj->addrObj2Proc(sym.st_value);
            return (PS_OK);
        }
        if (ld_object_name)
            return (PS_ERR);
    }
    return (PS_ERR);
}

void
ps_plog(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

ps_err_e
ps_pread(struct ps_prochandle *p, psaddr_t addr, void *buf, size_t len)
{
    try {
        p->readObj((intptr_t)addr, (char *)buf, len);
        return PS_OK;
    } 
    catch (...) {
        return PS_ERR;
    }
}

ps_err_e
ps_pstop(const struct ps_prochandle *p)
{
    abort();
    return (PS_ERR);
}

ps_err_e
ps_pwrite(struct ps_prochandle *p, psaddr_t addr, const void *buf, size_t len)
{
    return (PS_ERR);
}


#if defined(__FreeBSD__)
ps_err_e
ps_linfo(struct ps_prochandle *p, lwpid_t pid, void *info)
{
    if (p->pid == -1) {
        if (ptrace(PT_LWPINFO, pid, info,
            sizeof (struct ptrace_lwpinfo)) == -1)
                return (PS_ERR);
        else
                return (PS_OK);
    } else {
        memset(info, 0, sizeof(struct ptrace_lwpinfo));
        return PS_OK;
    }
}
#elif defined(__linux__)

struct PIDFinder {
    const Process *p;
    pid_t pid;
};

static enum NoteIter
procGetPid(void *cookie, const char *name, u_int32_t type, const void *datap, size_t len)
{
    if (type == NT_PRSTATUS) {
        PIDFinder *pf = (PIDFinder *)cookie;
        const prstatus_t *status = (const prstatus_t *)datap;
        pf->pid = status->pr_pid;
        return NOTE_DONE;
    }
    return NOTE_CONTIN;
}

pid_t
ps_getpid(struct ps_prochandle *p)
{
    return p->getPID();
}

pid_t
CoreProcess::getPID() const
{
    PIDFinder pf;
    pf.p = this;
    pf.pid = -1;
    coreImage.getNotes(procGetPid, &pf);
    std::clog << "got pid: " << pf.pid << std::endl;
    return pf.pid;
}

ps_err_e
ps_pdread(struct ps_prochandle *p, psaddr_t addr, void *d, size_t l)
{
    try {
        p->readObj((intptr_t)addr, (char *)d, l);
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

ps_err_e
ps_pdwrite(struct ps_prochandle *p, psaddr_t addr, const void *d, size_t l)
{
    abort();
    return PS_ERR;
}

ps_err_e
ps_ptread(struct ps_prochandle *p, psaddr_t addr, void *d, size_t l)
{
    abort();
    return PS_ERR;
}

ps_err_e
ps_ptwrite(struct ps_prochandle *p, psaddr_t addr, const void *d, size_t l)
{
    abort();
    return PS_ERR;
}


#endif

#ifdef __i386__
ps_err_e
ps_lgetxmmregs (struct ps_prochandle *ph, lwpid_t pid, char *xxx)
{
    abort();
    return (PS_ERR);
}

ps_err_e
ps_lsetxmmregs (struct ps_prochandle *ph, lwpid_t pid, const char *xxx)
{
    abort();
    return (PS_ERR);
}

#endif

#ifdef __amd64__

#endif

/*
 * Find the mapped object within which "addr" lies
 */
ElfObject *
ps_prochandle::findObject(Elf_Addr addr) const
{
    for (auto obj : objectList) {
        Elf_Addr va = obj->addrProc2Obj(addr);
        for (auto phdr : obj->programHeaders)
            if (va >= phdr->p_vaddr && va < phdr->p_vaddr + phdr->p_memsz)
                return obj;
    }
    return 0;
}
