#include <sys/ptrace.h>
#include <sys/types.h>

#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <wait.h>
#include <err.h>

#include <iostream>

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
LiveProcess::load(const PstackOptions &options)
{
    StopLWP here(this, pid);
    LiveReader live(pid, "auxv");
    processAUXV(live);
    Process::load(options);
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
        std::clog << "failed to detach from process " << pid << ": " << strerror(errno) << "\n";
    if (verbose >= 1) {
        timeval tv;
        gettimeofday(&tv, 0);
        long long secs = (tv.tv_sec - tcb.stoppedAt.tv_sec) * 1000000;
        secs += tv.tv_usec;
        secs -= tcb.stoppedAt.tv_usec;
        *debug << "resumed LWP " << pid << ": was stopped for " << std::dec << secs << " microseconds" << std::endl;
    }
}

void
LiveProcess::findLWPs()
{
    std::string dirName = procname(pid, "task");
    DIR *d;
    dirent *de;
    for (d = opendir(dirName.c_str()); d != nullptr && (de = readdir(d)) != nullptr; ) {
        char *p;
        lwpid_t pid = strtol(de->d_name, &p, 0);
        if (*p == 0) {
            (void)lwps[pid];
        }
    }
    closedir(d);
}

pid_t
LiveProcess::getPID() const
{
    return pid;
}

void
LiveProcess::stopProcess()
{
    if (verbose >= 1)
        *debug << "stopping process " << pid << "\n";
    stop(pid); // suspend the main process itself first.
    findLWPs();

    /*
     * suspend any threads that the thread-db knows about.
     * XXX: This doesn't actually work under linux: If we fail, just stop the LWP
     */
    listThreads([this] (const td_thrhandle_t *thr) {
        td_thrinfo_t info;
        td_thr_get_info(thr, &info);
        (void)lwps[info.ti_lid]; // make sure we have the LWP
        if (td_thr_dbsuspend(thr) == TD_NOCAPAB) {
            if (verbose >= 3)
                *debug << "can't suspend thread "  << thr << ": will suspend it's LWP " << info.ti_lid << "\n";
        } else if (verbose >= 3) {
            *debug << "suspended thread "  << thr << "(LWP " << info.ti_lid << ")\n";
        }
    });

    // Stop all LWPS.
    int i = 0;
    for (auto lwp = lwps.begin(); lwp != lwps.end(); ++lwp) {
        stop(lwp->first);
        i++;
    }
    if (verbose >= 1)
        *debug << "stopped process " << pid << "\n";
}

void
LiveProcess::resumeProcess()
{
    if (verbose >= 1)
        *debug << "resuming process " << pid << "\n";

    listThreads([this] (const td_thrhandle_t *thr) {
        if (td_thr_dbresume(thr) == TD_NOCAPAB) {
            td_thrinfo_t info;
            td_thr_get_info(thr, &info);
            if (verbose >= 3)
                *debug << "can't resume thread "  << thr << ": will resume it's LWP" << info.ti_lid << "\n";
        }
    });

    for (auto lwp = lwps.begin(); lwp != lwps.end(); ++lwp)
        resume(lwp->first);

    resume(pid);
    if (verbose >= 1)
        *debug << "resumed process " << pid << "\n";
}

void
LiveProcess::stop(lwpid_t pid)
{
    auto &tcb = lwps[pid];
    if (tcb.stopCount++ != 0)
        return;

    if (verbose >= 0)
        *debug << "stopping LWP " << pid << "\n";

    gettimeofday(&tcb.stoppedAt, 0);
    if (ptrace(PT_ATTACH, pid, 0, 0) == 0) {
        int status;
        pid_t waitedpid = waitpid(pid, &status, pid == this->pid ? 0 : __WCLONE);
        if (waitedpid != -1) {
            if (verbose >= 2)
                *debug << "stopped LWP " << pid << "\n";
            return;
        }
        if (verbose >= 2)
            *debug << "failed to stop LWP " << pid << ": wait failed: " << strerror(errno) << "\n";
        return;
    }
    if (verbose >= 2)
        *debug << "failed to stop LWP " << pid << ": ptrace failed: " << strerror(errno) << "\n";
}
