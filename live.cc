#include <iostream>
#include <unistd.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <wait.h>
#include <err.h>

#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"

std::string
procname(pid_t pid, const std::string &base)
{
    return linkResolve(stringify("/proc/", pid, "/", base));
}

LiveReader::LiveReader(pid_t pid, const std::string &base)
   : FileReader(procname(pid, base)) {}

LiveProcess::LiveProcess(std::shared_ptr<ElfObject> ex, pid_t pid_,
      const PathReplacementList &repls, DwarfImageCache &imageCache)
    : Process(ex ? ex : imageCache.getImageForName(procname(pid_, "exe")),
             std::make_shared<CacheReader>(std::make_shared<LiveReader>(pid_, "mem")),
          repls, imageCache)
    , pid(pid_)
    , stopCount(0)
{
}

void
LiveProcess::load()
{
    StopProcess here(this);
    LiveReader live(pid, "auxv");
    processAUXV(live);
    Process::load();
}

bool
LiveProcess::getRegs(lwpid_t pid, CoreRegisters *reg)
{
#ifdef __FreeBSD__
    int rc;
    rc = ptrace(PT_GETREGS, pid, (caddr_t)reg, 0);
    if (rc == -1) {
        warn("failed to trace LWP %d", (int)pid);
        return false;
    }
    return true;
#endif
#ifdef __linux__
    stop(pid);
    bool rc = ptrace(__ptrace_request(PTRACE_GETREGS), pid, 0, reg) != -1;
    resume(pid);
    return rc;
#endif
}

void
LiveProcess::resume(lwpid_t pid)
{
    auto &tcb = lwps[pid];
    assert(tcb.stopCount != 0); // We can't resume an LWP that is not suspended.
    if (--tcb.stopCount != 0)
        return;
    kill(pid, SIGCONT);
    if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
        std::clog << "failed to detach from process " << pid << ": " << strerror(errno);
    if (verbose) {
        timeval tv;
        gettimeofday(&tv, 0);
        long long secs = (tv.tv_sec - tcb.stoppedAt.tv_sec) * 1000000;
        secs += tv.tv_usec;
        secs -= tcb.stoppedAt.tv_usec;
        *debug << "resumed " << pid << ": was stopped for " << std::dec << secs << " microseconds" << std::endl;
    }
}

void
LiveProcess::stopProcess()
{
    stop(pid);
    // suspend everything quickly.
    listThreads([this] (const td_thrhandle_t *thr) {
        td_thrinfo_t info;
        td_thr_get_info(thr, &info);
        auto &tcb = lwps[info.ti_lid];
        if (td_thr_dbsuspend(thr) == TD_NOCAPAB) {
            /*
             * This doesn't actually work under linux: just add the LWP
             * to the list of stopped lwps.
             */
            if (verbose)
                *debug << "can't suspend thread "  << thr << ": will suspend it's LWP " << info.ti_lid << "\n";
        } else {
            tcb.hasThread = true;
            if (verbose)
                *debug << "suspended thread "  << thr << "\n";
        }
    });
    int i = 0;
    for (auto lwp = lwps.begin(); lwp != lwps.end(); ++lwp) {
        stop(lwp->first);
        i++;
    }
}

void
LiveProcess::resumeProcess()
{
    listThreads([] (const td_thrhandle_t *thr) { td_thr_dbresume(thr); } );
    for (auto lwp = lwps.begin(); lwp != lwps.end(); ++lwp)
        resume(lwp->first);
    resume(pid);
}

void
LiveProcess::stop(lwpid_t pid)
{
    auto &tcb = lwps[pid];
    if (tcb.stopCount++ != 0)
        return;

    gettimeofday(&tcb.stoppedAt, 0);

    if (ptrace(PT_ATTACH, pid, 0, 0) == 0) {
        int status;
        pid_t waitedpid = waitpid(pid, &status, pid == this->pid ? 0 : __WCLONE);
        if (waitedpid != -1) {
            if (verbose)
                *debug << "stopped LWP " << pid << "\n";
            return;
        }
        if (verbose)
            *debug << "failed to stop LWP " << pid << ": wait failed: " << strerror(errno) << "\n";
        return;
    }
    if (verbose)
        *debug << "failed to stop LWP " << pid << ": ptrace failed: " << strerror(errno) << "\n";
}
