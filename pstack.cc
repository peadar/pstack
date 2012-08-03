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
    Process *proc;
    lwpid_t pid;
    CoreRegisters *reg;
};

/*
 * Command-line flags
 */
static int gFrameArgs = 6;		/* number of arguments to print */
static int gMaxFrames = 1024;		/* max number of frames to read */
static int gShowObjectNames = 0;	/* show names of objects for each IP */
int gVerbose = 0;
static int gWantDwarf = 0;

/* Prototypes */
static int	usage(void);
static int	procThreadIterate(const td_thrhandle_t *thr, void *p);

static enum NoteIter procAddThreadsFromNotes(void *, const char *, u_int32_t,
			const void *, size_t);
static enum NoteIter procRegsFromNote(void *cookie, const char *name,
			u_int32_t type, const void *data, size_t len);

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
            gMaxFrames = strtol(optarg, &cp, 0);
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
            proc.load();
            proc.dumpStacks(stdout, 0);
        } else {
            LiveProcess proc(execData, pid);
            proc.load();
            proc.dumpStacks(stdout, 0);
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
        const Elf_auxv_t *aux = (const Elf_auxv_t *)datap;
        const Elf_auxv_t *eaux = aux + len / sizeof *aux;
        Elf_Addr hdr = 0;
        while (aux < eaux) {
            if (aux->a_type == AT_SYSINFO_EHDR)
                hdr = aux->a_un.a_val;
            aux++;
        }
        if (hdr) {
            Process *proc = (Process *)cookie;
            proc->vdso = new char[getpagesize()];
            if (proc->readMem(proc->vdso, hdr, getpagesize()) == size_t(getpagesize())) {
                MemReader *r = new MemReader(proc->vdso, getpagesize());
                proc->readers.push_back(r);
                ElfObject *elf = new ElfObject(*r);
                proc->addElfObject(elf, hdr);
            }
        }
        return NOTE_DONE;
    }
    return NOTE_CONTIN;
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

#ifdef NOTYET
    /*
     * Do our best to automatically find the executable.
     */
    if (exeName == 0) {
        if (coreImage != 0) {
            if (elfGetImageFromCore(p->coreImage, &exeName) != 0)
                exeName = 0;
        } else {
            snprintf(tmpBuf, sizeof(tmpBuf), "/proc/%d/file", pid);
            rc = readlink(tmpBuf, tmpBuf, sizeof(tmpBuf) - 1);
            if (rc != -1) {
                tmpBuf[rc] = 0;
                exeName = tmpBuf;
            }
        }
        if (!exeName) {
            warn("cannot find executable: try using \"-e\"");
            procClose(p); xxx delete p
            return -1;
        }
    }
#endif
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
ps_prochandle::load()
{

    td_err_e the;

    /* Attach any dynamically-linked libraries */
    loadSharedObjects();

    /*
     * Try to use thread_db to iterate over the threads.
     * If we can't, fall back to grabbing the PRSTATUS notes
     * from the core, or grab the registers via ptrace() if
     * debugging a live process.
     */
    the = td_ta_new(this, &agent);
    if (the == TD_OK) {
        td_ta_thr_iter(agent, procThreadIterate, this,
                TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
                TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
    }
    if (threadList.empty()) {
#ifdef NOTYET
        if (pid != -1) {
            if (ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0) == 0) {
                elf_regs elf;
                addThread(0, &regs, pid);
            } else
                warn("fetch non-threaded process registers");
        } else {
            coreImage.getNotes(procAddThreadsFromNotes, this);
        }
#endif

    }
}

const Elf_Phdr *
ElfObject::findHeaderForAddress(Elf_Addr pa)
{
    Elf_Addr va = addrProc2Obj(pa);
    for (auto hdr : programHeaders)
        if (hdr->p_vaddr <= va && hdr->p_vaddr + hdr->p_filesz > va && hdr->p_type == PT_LOAD)
            return hdr;
    return 0;
}

size_t
CoreProcess::readMem(char *ptr, Elf_Addr remoteAddr, size_t size)
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
            break;
        Elf_Addr addr = obj->addrProc2Obj(remoteAddr);
        size_t fragSize = MIN(hdr->p_vaddr + hdr->p_memsz - remoteAddr, size);
        obj->io.readObj(hdr->p_offset + addr - hdr->p_vaddr, ptr, fragSize);
        size -= fragSize;
        readLen += fragSize;
    }
    return readLen;
}

LiveProcess::LiveProcess(Reader &ex, pid_t pid_)
    : ps_prochandle(ex)
    , pid(pid_)
{
}

/*
 * Read data from the target's address space.
 */
size_t
LiveProcess::readMem(char *ptr, Elf_Addr remoteAddr, size_t size)
{
    size_t fragSize, readLen;
    unsigned char *cp;
    struct PageCache *pcache = &pageCache;

    /*
     * A simple LRU page cache, to avoid dragging pointer-sized
     * amounts of data across the ptrace interace.
     */
    int pagesize = getpagesize(), luGeneration;
    struct MappedPage *page, *luPage = 0;
    Elf_Addr pageLoc;
    for (readLen = 0; size; readLen += fragSize) {
        luGeneration = INT_MAX;
        pageLoc = remoteAddr - remoteAddr % pagesize;
        for (page = pcache->pages; page < pcache->pages + PAGECACHE_SIZE; page++) {

            /* Did we find the page we want? */
            if (page->address == pageLoc && page->data != NULL)
                break;

            /* No: keep an eye on least recently used */
            if (page->lastAccess < luGeneration) {
                luPage = page;
                luGeneration = page->lastAccess;
            }
        }
        if (page == pcache->pages + PAGECACHE_SIZE) {
            /*
             * Page not found: read entire page into
             * least-recently used cache slot
             */
            page = luPage;
            cp = new unsigned char[pagesize];
#ifdef PT_IO
            {
                struct ptrace_io_desc iod;
                iod.piod_op = PIOD_READ_D;
                iod.piod_offs = (void *)pageLoc;
                iod.piod_addr = cp;
                iod.piod_len = pagesize;

                rc = ptrace(PT_IO, p->pid, (caddr_t)&iod, 0);
                if (rc != 0 || iod.piod_len != (size_t)pagesize) {
                        free(cp);
                        return (readLen);
                }
            }
#endif

            if (page->data)
                delete[] page->data;
            page->data = cp;
            page->address = pageLoc;
        }
        /* This page has been recently used */
        page->lastAccess = ++pcache->accessGeneration;
        fragSize = MIN(size, pagesize - remoteAddr % pagesize);
        memcpy((char *)ptr + readLen, page->data + remoteAddr % pagesize, fragSize);
        remoteAddr += fragSize;
        size -= fragSize;
    }
    return (readLen);
}

Thread::Thread(Process *p, thread_t id, lwpid_t lwp, CoreRegisters regs)
    : running(0)
    , threadId(id)
    , lwpid(lwp)
{
    stackUnwind(p, regs);
}

void
Thread::stackUnwind(Process *p, CoreRegisters &regs)
{

    int frameCount, i;
    struct StackFrame *frame;
    Elf_Addr ip;

    stack.clear();

    /* Put a bound on the number of iterations. */
    for (frameCount = 0; frameCount < gMaxFrames; frameCount++) {
        frame = new StackFrame(ip = REG(regs, ip), REG(regs, bp));
        stack.push_back(frame);

        DwarfRegisters dr;
        dwarfPtToDwarf(&dr, &regs);

        if (gWantDwarf && (ip = dwarfUnwind(p, &dr, ip - 3)) != 0) {
            frame->unwindBy = "dwarf";
            dwarfDwarfToPt(&regs, &dr);
        } else {
            for (i = 0; i < gFrameArgs; i++) {
                Elf_Word arg;
                if (p->readMem((char *)&arg
                        , REG(regs, bp) + sizeof(Elf_Word) * 2 + i * sizeof(Elf_Word)
                        , sizeof(Elf_Word)) != sizeof(Elf_Word))
                    break;
                frame->args.push_back(arg);
            }
            frame->unwindBy = "END  ";
            /* Read the next frame */
            if (p->readMem((char *)&ip, REG(regs, bp) + sizeof(REG(regs, bp)), sizeof ip) != sizeof(ip))
                break;
            REG(regs, ip) = ip;
            // XXX: if no return instruction, break out.
            if (ip == 0)
                    break;
            // Read new frame pointer from stack.
            if (p->readMem((char *)&REG(regs, bp), REG(regs, bp), sizeof(REG(regs, bp))) != sizeof(REG(regs, bp)))
                break;
            // XXX: If new frame pointer is lower than old one,
            // there's a problem.
            if ((uintmax_t)REG(regs, bp) <= frame->bp)
                break;
            frame->unwindBy = "stdc  ";
        }
    }
}

/*
 * Take a snapshot of a thread from a set of registers.
 * This is the x86-specific bit.
 */
void
ps_prochandle::addThread(thread_t id, const CoreRegisters &regs, lwpid_t lwp)
{
    threadList.push_back(new Thread(this, id, lwp, regs));
}

/*
 * Print a stack trace of each stack in the process
 */
void
ps_prochandle::dumpStacks(FILE *file, int indent)
{
    struct ElfObject *obj;
    int lineNo;
    Elf_Sym sym;
    std::string fileName;
    const char *padding;
    std::string symName;

    padding = pad(indent);
    fprintf(file, "%s", padding);

#ifdef NOTYET
    if (p->pid != -1)
        fprintf(file, "(process %d)", p->pid);
    else
        fprintf(file, "(core file \"%s\")", p->coreImage.fileName);
    fprintf(file, ", executable \"%s\"\n", p->execImage->fileName);
#endif

    for (auto thread : threadList) {
        fprintf(file, "%s----------------- thread %lu (LWP %ld) ", padding, (unsigned long)thread->threadId, (unsigned long)thread->lwpid);
        if (thread->running)
                printf("(running) ");
        fprintf(file, "-----------------\n");
        for (auto frame : thread->stack) {
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
    struct link_map map;
    char prefixedPath[PATH_MAX + 1], *path;

    /* Does this process look like it has shared libraries loaded? */
    Elf_Addr r_debug_addr = findRDebugAddr();
    if (r_debug_addr == 0 || r_debug_addr == (Elf_Addr)-1)
        return;

    struct r_debug rDebug;
    if (readMem((char *)&rDebug, r_debug_addr, sizeof(rDebug)) != sizeof(rDebug))
        return;

    if (abiPrefix != "") {
        path = prefixedPath + snprintf(prefixedPath, sizeof(prefixedPath), "%s", abiPrefix.c_str());
        maxpath = PATH_MAX - strlen(abiPrefix.c_str());
    } else {
        path = prefixedPath;
        maxpath = PATH_MAX;
    }

    /* Iterate over the r_debug structure's entries, loading libraries */
    for (Elf_Addr mapAddr = (Elf_Addr)rDebug.r_map; mapAddr; mapAddr = (Elf_Addr)map.l_next) {
        if (readMem((char *)&map, mapAddr, sizeof(map)) != sizeof(map)) {
            warnx("cannot read link_map @ %p", (void *)mapAddr);
            break;
        }
        /* Read the path to the file */
        if (map.l_name == 0 || readMem(path, (Elf_Addr)map.l_name, maxpath) <= 0)
            continue;
        Elf_Addr lAddr = (Elf_Addr)map.l_addr;

        if (abiPrefix != "" && access(prefixedPath, R_OK) == 0)
            path = prefixedPath;
        FileReader *f = new FileReader(path);
        readers.push_back(f);
        addElfObject(new ElfObject(*f), lAddr);
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
        if (dyn.d_tag == DT_DEBUG
                && readMem((char *)&dyn, execImage->dynamic->p_vaddr + dynOff, sizeof(dyn)) == sizeof(dyn))
            return dyn.d_un.d_ptr;
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

static enum NoteIter
procAddThreadsFromNotes(void *cookie, const char *name, u_int32_t type,
    const void *data, size_t len)
{

    const prstatus_t *prstatus = (const prstatus_t *)data;
    Process *p = (Process *)cookie;
    if (strcmp(name, PRSTATUS_NOTENAME) == 0 && type == NT_PRSTATUS)
        p->addThread(0, *(const CoreRegisters *)&prstatus->pr_reg, prstatus->pr_pid);

    return (NOTE_CONTIN);
}

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
CoreProcess::getRegs(lwpid_t pid, CoreRegisters *reg)
{
    struct RegnoteInfo rni;
    rni.proc = this;
    rni.pid = pid;
    rni.reg = reg;
    return coreImage.getNotes(procRegsFromNote, &rni);
}

int
LiveProcess::getRegs(lwpid_t pid, CoreRegisters *reg)
{
#ifdef __FreeBSD__
    int rc;
    rc = ptrace(PT_GETREGS, pid, (caddr_t)reg, 0);
    if (rc == -1)
        warn("failed to trace LWP %d", (int)pid);
    return (rc);
#endif
    abort();
    return -1;
}

/*
 * Setup what we need to read from the process memory (or core file)
 */
void
LiveProcess::stop()
{
    int status;

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
#if defined(__FreeBSD__) && !defined(MISC_39201_FIXED)
        if (errno != ECHILD || waitpid(pid, &status, WLINUXCLONE) == -1)
            warnx("(linux thread process detected: waiting with WLINUXCLONE)");
        else
#endif
            warn("can't wait for child: all bets " "are off");
    }
}

void
LiveProcess::resume()
{
    if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
        warn("failed to detach from process %d", pid);
}

/*
 * Free any resources associated with a Process
 */
Process::~Process()
{
    delall(objectList);
    delall(threadList);
    delete[] vdso;
}

Thread::~Thread()
{
    delall(stack);
}

#ifdef __linux__
#define THR_ID(t) ((intptr_t)(t)->th_unique)
#else
#define THR_ID(t) ((t)->th_tid)
#endif

/*
 * Callback for threaddb iterator function
 */
static int
procThreadIterate(const td_thrhandle_t *thr, void *v)
{
    CoreRegisters regs;
    td_thrinfo_t ti;
    td_err_e the;
    Process *p;

    p = (Process *)v;
#ifdef __linux__ // XXX: looks wrong on linux, right on BSD
    the = td_thr_getgregs(thr, (elf_greg_t *) &regs);
#else
    the = td_thr_getgregs(thr, &regs);
#endif
    if (the == TD_OK) {
        td_thr_get_info(thr, &ti);
        p->addThread(THR_ID(thr), regs, ti.ti_lid);
    } else {
        warn("cannot trace thread %lu", (unsigned long)THR_ID(thr));
    }
    return (0);
}

/*
 * A very basic proc_service implementation.
 * Those functions that are not required for pstack abort().
 */

ps_err_e ps_lcontinue(const struct ps_prochandle *p, lwpid_t pid)
{
    abort();
    return (PS_ERR);
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

ps_err_e ps_lstop(const struct ps_prochandle *p, lwpid_t pid)
{
    abort();
    return (PS_ERR);
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
    size_t rc;

    rc = p->readMem((char *)buf, (Elf_Addr)addr, len);
    return (rc == len ? PS_OK : PS_ERR);
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
    Process *p;
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
CoreProcess::getPID()
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
    return p->readMem((char *)d, (Elf_Addr)addr, l) == l ? PS_OK : PS_ERR;
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
ps_prochandle::findObject(Elf_Addr addr)
{
    for (auto obj : objectList) {
        Elf_Addr va = obj->addrProc2Obj(addr);
        for (auto phdr : obj->programHeaders)
            if (va >= phdr->p_vaddr && va < phdr->p_vaddr + phdr->p_memsz)
                return obj;
    }
    return 0;
}
