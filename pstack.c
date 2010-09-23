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

/*
 * ps_prochandle should be declared before including thread_db.h to
 * avoid warnings
 */

#include <thread_db.h>
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
static Elf_Addr procFindRDebugAddr(Process *p);
static int	procOpen(pid_t pid, const char *exeName, const char *coreFile,
			Process **procp);
static int	procDumpStacks(FILE *file, Process *p, int indent);
static void	procAddElfObject(Process *p, struct ElfObject *obj,
			Elf_Addr base);
static void	procClose(Process *p);
static void	procFreeThreads(Process *p);
static void	procFreeObjects(Process *p);
static void	procLoadSharedObjects(Process *p);
static int	procGetRegs(Process *p, lwpid_t pid, CoreRegisters *reg);
static int	procOpenLive(Process *p, pid_t pid, const char *core);
static void	procCloseLive(Process *p);
static int	usage(void);
static int	procThreadIterate(const td_thrhandle_t *thr, void *p);
static void	procAddThread(Process *p, thread_t id, const CoreRegisters *regs, lwpid_t);

static enum NoteIter procAddThreadsFromNotes(void *, const char *, u_int32_t,
			const void *, size_t);
static enum NoteIter procRegsFromNote(void *cookie, const char *name,
			u_int32_t type, const void *data, size_t len);


static void
dwarf(struct ElfObject *obj)
{
    char error[1024];
    DwarfInfo *dwarf = dwarfLoad(0, obj, stderr);
    if (dwarf)
        dwarfDump(stdout, 0, dwarf);
    else
        fprintf(stderr, "can't load DWARF: %s", error);
}

int
main(int argc, char **argv)
{
    const char *coreFile, *execFile;
    char *cp;
    int error, i, c, snap;
    Process *p;
    pid_t pid;
    struct ElfObject *dumpObj;

    execFile = NULL;
    snap = 64;

    while ((c = getopt(argc, argv, "a:d:D:e:f:hloOs:v")) != -1) {
        switch (c) {
        case 'a':
            gFrameArgs = atoi(optarg);
            break;

        case 'l':
            gWantDwarf = 1;
            break;

        case 'D':
            if (elfLoadObject(optarg, &dumpObj) == 0) {
                    dwarf(dumpObj);
                    return (0);
            } else {
                    return (-1);
            }
            break;

        case 'd':
            /* Undocumented option to dump image contents */
            if (elfLoadObject(optarg, &dumpObj) == 0) {
                    elfDumpObject(stdout, dumpObj, snap, 0);
                    return (0);
            } else {
                    return (-1);
            }
            break;

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

        case 's':
            snap = atoi(optarg);
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
        if (pid == 0 || (kill(pid, 0) == -1 && errno == ESRCH)) {
            /* Assume argv[i] is a core file */
            coreFile = argv[i];
            pid = -1;
        } else {
            /* Assume argv[i] is a pid */
            coreFile = 0;
        }
        if (procOpen(pid, execFile, coreFile, &p) == 0) {
            procDumpStacks(stdout, p, 0);
            procClose(p);
        } else {
            error = EX_OSERR;
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
        const Elf_auxv_t *aux = datap;
        const Elf_auxv_t *eaux = aux + len / sizeof *aux;
        Elf32_Addr hdr = 0, load = 0;
        while (aux < eaux) {
            if (aux->a_type == AT_SYSINFO_EHDR)
                hdr = aux->a_un.a_val;
            if (aux->a_type == AT_SYSINFO)
                load = aux->a_un.a_val;
            aux++;
        }
        if (load && hdr) {
            Process *proc = cookie;
            proc->vdso = malloc(getpagesize());
            if (procReadMem(proc, proc->vdso, hdr, getpagesize()) == getpagesize()) {
                struct ElfObject *elf;
                if (elfLoadObjectFromData(proc->vdso, getpagesize(), &elf) == 0) {
                    elf->fileName = "vdso";
                    procAddElfObject(proc, elf, hdr);
                }
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

static int
procOpen(pid_t pid, const char *exeName, const char *coreFile, Process **procp)
{
    char tmpBuf[PATH_MAX];
    Process *p;
    td_err_e the;
    int rc, i;

    p = malloc(sizeof(*p));
    memset(p, 0, sizeof *p);
    p->objectList = NULL;
    p->threadList = NULL;
    p->objectCount = 0;
    p->coreImage = NULL;
    p->pid = -1;
    for (i = 0; i < PAGECACHE_SIZE; i++)
        p->pageCache.pages[i].data = 0;
    p->pageCache.accessGeneration = 0;

    if (coreFile && elfLoadObject(coreFile, &p->coreImage) != 0) {
        warn("cannot open corefile");
        procClose(p);
        return (-1);
    }

    /*
     * Do our best to automatically find the executable.
     */
    if (exeName == 0) {
        if (p->coreImage != 0) {
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
            procClose(p);
            return -1;
        }
    }

    /* read executable image */
    if (elfLoadObject(exeName, &p->execImage)) {
        procClose(p);
        return (-1);
    }

    p->abiPrefix = elfGetAbiPrefix(p->execImage);

    /* Add the image to the list of loaded objects. */
    procAddElfObject(p, p->execImage, 0);
    /* An executable is loaded at its own base address */
    p->execImage->load = p->execImage->base;

    /*
     * Get access to the address space of live process.
     * Note that while we have access to a live process, it is
     * effectively suspended, so we cannot spend too long between here
     * and the procCloseLive().
     */
    if (pid != -1 && procOpenLive(p, pid, coreFile) != 0) {
        procClose(p);
        return (-1);
    }
    /* Attach any dynamically-linked libraries */
    procLoadSharedObjects(p);
#ifdef __linux__
    /* Find the linux-gate VDSO, and treat as an ELF file */
    elfGetNotes(p->coreImage, procAddVDSO, p);
#endif


    /*
     * Try to use thread_db to iterate over the threads.
     * If we can't, fall back to grabbing the PRSTATUS notes
     * from the core, or grab the registers via ptrace() if
     * debugging a live process.
     */
    the = td_ta_new(p, &p->agent);
    if (the == TD_OK) {
        td_ta_thr_iter(p->agent, procThreadIterate, p,
                TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
                TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
    }
    if (p->threadList == 0) {
#ifdef XXX
        if (pid != -1) {
            if (ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0) == 0) {
                elf_regs elf;
                procAddThread(p, 0, &regs, pid);
            } else
                warn("fetch non-threaded process registers");
        } else
#endif
        {
            elfGetNotes(p->coreImage, procAddThreadsFromNotes, p);
        }
    }
    if (pid != -1)
            procCloseLive(p);
    *procp = p;
    return (0);
}

static const Elf_Phdr *
procFindHeaderForAddress(Process *p, const struct ElfObject *obj, Elf_Addr pa)
{
    const Elf_Phdr **hdr;
    Elf_Addr va = elfAddrProc2Obj(obj, pa);
    for (hdr = obj->programHeaders; *hdr; hdr++) {
        if ((*hdr)->p_vaddr <= va && (*hdr)->p_vaddr + (*hdr)->p_filesz > va) {
            if ((*hdr)->p_type == PT_LOAD)
                return *hdr;
        }
    }
    return 0;
}

/*
 * Read data from the target's address space.
 */
size_t
procReadMem(Process *p, void *ptr, Elf_Addr remoteAddr, size_t size)
{
    size_t fragSize, readLen;
    const Elf_Phdr *hdr;
    const unsigned char *data;
    unsigned char *cp;
    struct PageCache *pcache = &p->pageCache;

    pcache = &p->pageCache;
    readLen = 0;

    if (p->pid != -1) {
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
                cp = malloc(pagesize);
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
                        free(page->data);
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
    } else {
        /* Locate "remoteAddr" in the core file */
        while (size) {
            const struct ElfObject *obj = p->coreImage;
            hdr = procFindHeaderForAddress(p, obj, remoteAddr);
            if (hdr == 0)
                for (obj = p->objectList; obj != 0; obj = obj->next) {
                    hdr = procFindHeaderForAddress(p, obj, remoteAddr);
                    if (hdr)
                        break;
                }
            if (hdr != 0) {
                Elf_Addr addr = elfAddrProc2Obj(obj, remoteAddr);
                fragSize = MIN(hdr->p_vaddr + hdr->p_memsz - remoteAddr, size);
                data = obj->fileData + hdr->p_offset + addr - hdr->p_vaddr;
                memcpy((char *)ptr + readLen, data, fragSize);
                size -= fragSize;
                readLen += fragSize;
            } else {
                return (readLen);
            }
        }
        return (readLen);
    }
}

static void
stackUnwind(Process *p, struct Thread *thread, CoreRegisters *regs)
{

    int frameCount, i;
    struct StackFrame *frame;
    const int frameSize = sizeof(*frame) + sizeof(Elf_Word) * gFrameArgs;
    Elf_Addr ip;

    STAILQ_INIT(&thread->stack);

    /* Put a bound on the number of iterations. */
    for (frameCount = 0; frameCount < gMaxFrames; frameCount++) {
        frame = calloc(1, frameSize);
        frame->ip = ip = REG(*regs, ip);
        frame->bp = REG(*regs, bp);
        STAILQ_INSERT_TAIL(&thread->stack, frame, link);

        DwarfRegisters dr;
        dwarfPtToDwarf(&dr, regs);

        if (gWantDwarf && (ip = dwarfUnwind(p, &dr, ip - 3)) != 0) {
            frame->argCount = 0;
            frame->unwindBy = "dwarf";
            dwarfDwarfToPt(regs, &dr);
        } else {
            for (i = 0; i < gFrameArgs; i++)
                    if (procReadMem(p, &frame->args[i],
                        REG(*regs, bp) + sizeof(Elf_Word) * 2 +
                        i * sizeof(Elf_Word), sizeof(Elf_Word)) !=
                        sizeof(Elf_Word))
                            break;
            frame->argCount = i;
            frame->unwindBy = "END  ";
            /* Read the next frame */
            if (procReadMem(p, &ip,
                REG(*regs, bp) + sizeof(REG(*regs, bp)), sizeof ip)
                != sizeof(ip))
                    break;
            REG(*regs, ip) = ip;
            // XXX: if no return instruction, break out.
            if (ip == 0)
                    break;
            // Read new frame pointer from stack.
            if (procReadMem(p, &REG(*regs, bp), REG(*regs, bp),
                sizeof(REG(*regs, bp))) != sizeof(REG(*regs, bp)))
                    break;
            // XXX: If new frame pointer is lower than old one,
            // there's a problem.
            if ((uintmax_t)REG(*regs, bp) <= frame->bp)
                    break;
            frame->unwindBy = "stdc  ";
        }
    }
}
 
/*
 * Take a snapshot of a thread from a set of registers.
 * This is the x86-specific bit.
 */
static void
procAddThread(Process *p, thread_t id, const CoreRegisters *regsp, lwpid_t lwp)
{
    struct Thread *thread;

    thread = malloc(sizeof(struct Thread));
    thread->running = 0;

    CoreRegisters regs = *regsp;

    stackUnwind(p, thread, &regs);

    thread->threadId = id;
    thread->lwpid = lwp;
    thread->next = p->threadList;
    p->threadList = thread;
}

/*
 * Print a stack trace of each stack in the process
 */
static int
procDumpStacks(FILE *file, Process *p, int indent)
{
    struct StackFrame *frame;
    struct ElfObject *obj;
    int i, lineNo;
    struct Thread *thread;
    const Elf_Sym *sym;
    const char *fileName, *symName, *cp, *padding;

    padding = pad(indent);
    fprintf(file, "%s", padding);

    if (p->pid != -1)
        fprintf(file, "(process %d)", p->pid);
    else
            fprintf(file, "(core file \"%s\")", p->coreImage->fileName);

    fprintf(file, ", executable \"%s\"\n", p->execImage->fileName);
    for (thread = p->threadList; thread; thread = thread->next) {
        fprintf(file, "%s----------------- thread %lu (LWP %ld) ",
            padding, (unsigned long)thread->threadId, (unsigned long)thread->lwpid);
        if (thread->running)
                printf("(running) ");
        fprintf(file, "-----------------\n");
        STAILQ_FOREACH(frame, &thread->stack, link) {
            symName = fileName = "????????";
            sym = NULL;
            Elf_Addr objIp;
            if (procFindObject(p, frame->ip, &obj) == 0) {
                fileName = obj->fileName;
                elfFindSymbolByAddress(obj, elfAddrProc2Obj(obj, frame->ip), STT_FUNC, &sym, &symName);
                objIp = elfAddrProc2Obj(obj, frame->ip);
            } else {
                obj = 0;
                objIp = 0;
            }
            fprintf(file, "%s%6.16p ", padding - 1, (void *)frame->ip);
            if (gVerbose) { /* Show ebp for verbose */
#ifdef i386
                fprintf(file, "%p ", (void *)frame->bp);
#endif
                fprintf(file, "%s ", frame->unwindBy);
            }

            fprintf(file, "%s (", symName);
            if (frame->argCount) {
                for (i = 0; i < frame->argCount - 1; i++)
                    fprintf(file, "%x, ", frame->args[i]);
                fprintf(file, "%x", frame->args[i]);
            }
            fprintf(file, ")");
            if (obj != 0) {
                if (sym != NULL)
                    printf(" + %p", (void *)((intptr_t)objIp - sym->st_value));
                if (gShowObjectNames)
                    printf(" in %s", gShowObjectNames > 1 || !(cp = strrchr(obj->fileName, '/')) ? obj->fileName : cp + 1);
                if (obj->dwarf && dwarfSourceFromAddr(obj->dwarf, objIp - 1, &fileName, &lineNo))
                    printf(" (source %s:%d)", fileName, lineNo);
            }
            printf("\n");
        }
        fprintf(file, "\n");
    }
    return (0);
}

/*
 * Add ELF object description into process.
 */
static void
procAddElfObject(Process *p, struct ElfObject *obj, Elf_Addr load)
{
    obj->load = load;
    obj->base = (Elf_Addr)-1;
    for (const Elf_Phdr **hdrp = obj->programHeaders; *hdrp; hdrp++) {
        const Elf_Phdr *hdr = *hdrp;
        if (hdr->p_type == PT_LOAD && hdr->p_vaddr < obj->base)
            obj->base = hdr->p_vaddr;
    }
    obj->next = p->objectList;
    p->objectList = obj;
    p->objectCount++;

    if (gVerbose) {
        fprintf(stderr, "object %s loaded at address %p, base=%p\n",
            obj->fileName, (void *)obj->load, (void *)obj->base);
    }

    if (gWantDwarf) {
        DwarfInfo *di = obj->dwarf = dwarfLoad(p, obj, stderr);
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
static void
procLoadSharedObjects(Process *p)
{
    int loaded, maxpath;
    struct r_debug rDebug;
    struct link_map map;
    Elf_Addr mapAddr, lAddr, r_debug_addr;
    char prefixedPath[PATH_MAX + 1], *path;
    struct ElfObject *obj;

    /* Does this process look like it has shared libraries loaded? */
    r_debug_addr = procFindRDebugAddr(p);
    if (r_debug_addr == 0 || r_debug_addr == (Elf_Addr)-1)
        return;

    if (procReadMem(p, &rDebug, r_debug_addr, sizeof(rDebug)) != sizeof(rDebug))
        return;

    if (p->abiPrefix) {
        path = prefixedPath + snprintf(prefixedPath, sizeof(prefixedPath), "%s", p->abiPrefix);
        maxpath = PATH_MAX - strlen(p->abiPrefix);
    } else {
        path = prefixedPath;
        maxpath = PATH_MAX;
    }

    /* Iterate over the r_debug structure's entries, loading libraries */
    for (mapAddr = (Elf_Addr)rDebug.r_map; mapAddr; mapAddr = (Elf_Addr)map.l_next) {
        if (procReadMem(p, &map, mapAddr, sizeof(map)) != sizeof(map)) {
            warnx("cannot read link_map @ %p", (void *)mapAddr);
            break;
        }
        /* Read the path to the file */
        if (map.l_name == 0 || procReadMem(p, path, (Elf_Addr)map.l_name, maxpath) <= 0)
            continue;
        lAddr = (Elf_Addr)map.l_addr;
        if (p->abiPrefix && access(prefixedPath, R_OK) == 0)
            loaded = !elfLoadObject(prefixedPath, &obj);
        else
            loaded = !elfLoadObject(path, &obj);
        if (!loaded)
            continue;
        procAddElfObject(p, obj, lAddr);
    }
}

/*
 * Grab various bits of information from the run-time linker.
 */
static Elf_Addr
procFindRDebugAddr(Process *p)
{
    struct ElfObject *obj;
    Elf_Dyn dyno;
    const Elf_Dyn *dynp;
    Elf_Addr dyn;

    obj = p->execImage;
    /* Find DT_DEBUG in the process's dynamic section. */
    if (obj->dynamic) {
        for (dyn = 0; dyn < obj->dynamic->p_filesz; dyn += sizeof(Elf_Dyn)) {
            dynp = (const Elf_Dyn *)(obj->fileData +
                obj->dynamic->p_offset + dyn);
            if (dynp->d_tag == DT_DEBUG && procReadMem(p, &dyno,
                obj->dynamic->p_vaddr + dyn,
                sizeof(dyno)) == sizeof(dyno))
                    return(dyno.d_un.d_ptr);
        }
    }
    return (0);
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
    Process *p = cookie;
    if (strcmp(name, PRSTATUS_NOTENAME) == 0 && type == NT_PRSTATUS)
        procAddThread(p, 0, (const CoreRegisters *)&prstatus->pr_reg, prstatus->pr_pid);

    return (NOTE_CONTIN);
}

static enum NoteIter
procRegsFromNote(void *cookie, const char *name, u_int32_t type,
    const void *data, size_t len)
{
    const prstatus_t *prstatus;
    struct RegnoteInfo *rni;

    prstatus = (const prstatus_t *)data;
    rni = cookie;
    if (strcmp(name, PRSTATUS_NOTENAME) == 0 && type == NT_PRSTATUS && prstatus->pr_pid == rni->pid) {
            memcpy(rni->reg, (const DwarfRegisters *)&prstatus->pr_reg, sizeof(*rni->reg));
            return (NOTE_DONE);
    }
    return (NOTE_CONTIN);
}

static int
procGetRegs(Process *p, lwpid_t pid, CoreRegisters *reg)
{
    struct RegnoteInfo rni;
    int rc;

#ifdef __FreeBSD__
    if (p->pid != -1) {
        rc = ptrace(PT_GETREGS, pid, (caddr_t)reg, 0);
        if (rc == -1)
            warn("failed to trace LWP %d", (int)pid);
    }
    else
#endif
    {
        /* Read from core file. */
        rni.proc = p;
        rni.pid = pid;
        rni.reg = reg;
        rc = elfGetNotes(p->coreImage, procRegsFromNote, &rni);
    }
    return (rc);
}

/*
 * Setup what we need to read from the process memory (or core file)
 */
static int
procOpenLive(Process *p, pid_t pid, const char *core)
{
    int status;

    if (ptrace(PT_ATTACH, pid, 0, 0) != 0) {
        warn("failed to attach to process %d", pid);
        return (-1);
    }
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
    p->pid = pid;
    return (0);
}

static void
procCloseLive(Process *p)
{
    if (p->pid != -1) {
        if (ptrace(PT_DETACH, p->pid, (caddr_t)1, 0) != 0)
            warn("failed to detach from process %d", p->pid);
    }
}

/*
 * Free any resources associated with a Process
 */
static void
procClose(Process *p)
{
    size_t i;

    procFreeObjects(p);
    procFreeThreads(p);
    if (p->pid != -1) {
        for (i = 0; i < PAGECACHE_SIZE; i++)
            if (p->pageCache.pages[i].data)
                free(p->pageCache.pages[i].data);
    }
    if (p->coreImage)
        elfUnloadObject(p->coreImage);
    free(p);
}

/*
 * Release resources associated with the thread list
 */
static void
procFreeThreads(Process *p)
{
    struct StackFrameList *stackFrameList;
    struct StackFrame *frame;
    struct Thread *thread, *nextThread;

    for (thread = p->threadList; thread; thread = nextThread) {
        stackFrameList = &thread->stack;
        while (!STAILQ_EMPTY(stackFrameList)) {
                frame = STAILQ_FIRST(stackFrameList);
                STAILQ_REMOVE_HEAD(stackFrameList, link);
                free(frame);
        }
        nextThread = thread->next;
        free(thread);
    }
}

/*
 * Release the loaded ELF objects
 */
static void
procFreeObjects(Process *p)
{
    struct ElfObject *obj, *nextObj;

    for (obj = p->objectList; obj; obj = nextObj) {
        nextObj = obj->next;
        if (obj->fileData == p->vdso) {
            free(p->vdso);
            obj->fileData = 0;
        }
        elfUnloadObject(obj);
    }
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
        procAddThread(p, THR_ID(thr), &regs, ti.ti_lid);
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
    return (PS_ERR);
}

ps_err_e ps_lgetfpregs(struct ps_prochandle *p, lwpid_t pid, prfpregset_t *fpregsetp)
{
    return (PS_ERR);
}

ps_err_e ps_lgetregs(struct ps_prochandle *p, lwpid_t pid, prgregset_t gregset)
{
    return (procGetRegs(p, pid, gregset) == 0 ? PS_OK : PS_ERR);
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
    struct ElfObject *obj;
    const Elf_Sym *sym;

    for (obj = p->objectList; obj; obj = obj->next) {
        const char *p = strrchr(obj->fileName, '/');
        if (ld_object_name == 0 || strcmp(p ? p + 1 : obj->fileName, ld_object_name) == 0) {
            if (elfFindSymbolByName(obj, ld_symbol_name, &sym) == 0) {
                *ld_symbol_addr = (psaddr_t)elfAddrObj2Proc(obj, sym->st_value);
                return (PS_OK);
            }
            if (ld_object_name)
                return (PS_ERR);
        }
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

    rc = procReadMem(p, buf, (Elf_Addr)addr, len);
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
pid_t
ps_getpid(struct ps_prochandle *p)
{
    abort();
    return -1;
}

ps_err_e
ps_pdread(struct ps_prochandle *p, psaddr_t addr, void *d, size_t l)
{
    int rc = procReadMem(p, d, (Elf_Addr)addr, l);
    return rc  == l ? PS_OK : PS_ERR;
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
