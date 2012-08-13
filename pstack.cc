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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <iostream>
#include <set>
#include "dwarf.h"
#include "dump.h"

extern "C" {
#include <thread_db.h>
#include "proc_service.h"
}

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

/*
 * Command-line flags
 */
static int gFrameArgs = 6;		/* number of arguments to print */
static size_t gMaxFrames = 1024;		/* max number of frames to read */
static int gShowObjectNames = 0;	/* show names of objects for each IP */
int gVerbose = 0;

/* Prototypes */
static int usage(void);


static void
dwarf(struct ElfObject *obj)
{
    std::cout << DwarfInfo(obj);
}

void
Process::pstack()
{
    load();
    std::set<pid_t> lwps;

    // suspend everything quickly.
    listThreads(
        [&lwps] (const td_thrhandle_t *thr) -> void {
            if (td_thr_dbsuspend(thr) == TD_NOCAPAB) {
                td_thrinfo_t info;
                td_thr_get_info(thr, &info);
                lwps.insert(info.ti_lid);
            }});

    for (auto lwp : lwps)
        stop(lwp);

    std::list<ThreadStack> threadStacks;

    // get its back trace.

    listThreads(
        [&threadStacks, this](const td_thrhandle_t *thr) {
            CoreRegisters regs;
            td_err_e the;
#ifdef __linux__
            the = td_thr_getgregs(thr, (elf_greg_t *) &regs);
#else
            the = td_thr_getgregs(thr, &regs);
#endif
            if (the == TD_OK) {
                threadStacks.push_back(ThreadStack());
                threadStacks.back().unwind(*this, regs);
            }
    });

    if (threadStacks.empty()) {
        // get the register for the process itself, and use those.
        CoreRegisters regs;
        getRegs(ps_getpid(this),  &regs);
        threadStacks.push_back(ThreadStack());
        threadStacks.back().unwind(*this, regs);
    }


    for (auto s : threadStacks)
        dumpStack(stdout, 0, s, gVerbose);

    listThreads([](const td_thrhandle_t *thr) { td_thr_dbresume(thr); }); 
    // resume each lwp
    for (auto lwp : lwps)
        resume(lwp);
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
            proc.pstack();
        } else {
            LiveProcess proc(execData, pid);
            proc.pstack();
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

void
ThreadStack::unwind(Process &p, CoreRegisters &regs)
{
    stack.clear();
    /* Put a bound on the number of iterations. */
    for (size_t frameCount = 0; frameCount < gMaxFrames; frameCount++) {
        Elf_Addr ip;
        StackFrame *frame = new StackFrame(ip = REG(regs, ip), REG(regs, bp));
        stack.push_back(frame);

        DwarfRegisters dr;
        dwarfPtToDwarf(&dr, &regs);

        // try dwarf first...
        if ((ip = dwarfUnwind(p, &dr, ip)) != 0) {
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
