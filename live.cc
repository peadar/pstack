#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"

#include <sys/ptrace.h>
#include <sys/types.h>

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <wait.h>

#include <climits>
#include <iostream>
#include <utility>

std::string
procname(pid_t pid, const std::string &base)
{
    return linkResolve(stringify("/proc/", pid, "/", base));
}

LiveReader::LiveReader(pid_t pid, const std::string &base)
   : FileReader(procname(pid, base)) {}

LiveProcess::LiveProcess(Elf::Object::sptr &ex, pid_t pid_,
            const PathReplacementList &repls, Dwarf::ImageCache &imageCache)
    : Process(
            ex ? ex : imageCache.getImageForName(procname(pid_, "exe")),
            std::make_shared<CacheReader>(std::make_shared<LiveReader>(pid_, "mem")),
            repls, imageCache)
    , pid(pid_)
{
    (void)ps_getpid(this);
}

void
LiveProcess::load(const PstackOptions &options)
{
    StopLWP here(this, pid);
    processAUXV(LiveReader(pid, "auxv"));
    Process::load(options);
}

bool
LiveProcess::getRegs(lwpid_t pid, Elf::CoreRegisters *reg)
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
    iovec iov;
    iov.iov_base = reg;
    iov.iov_len = sizeof *reg;
    int rc= ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) != -1;
    resume(pid);
    return rc == 0;
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
    if (ptrace(PT_DETACH, pid, caddr_t(1), 0) != 0)
        std::clog << "failed to detach from process " << pid << ": " << strerror(errno) << "\n";
    if (verbose >= 1) {
        timeval tv;
        gettimeofday(&tv, nullptr);
        intmax_t usecs = (tv.tv_sec - tcb.stoppedAt.tv_sec) * 1000000;
        usecs += tv.tv_usec;
        usecs -= tcb.stoppedAt.tv_usec;
        *debug << "resumed LWP " << pid << ": was stopped for " << std::dec << usecs << " microseconds" << std::endl;
    }
}

void
LiveProcess::findLWPs()
{
    std::string dirName = procname(pid, "task");
    DIR *d = opendir(dirName.c_str());
    dirent *de;
    if (d != nullptr) {
        while ((de = readdir(d)) != nullptr) {
            char *p;
            lwpid_t pid = strtol(de->d_name, &p, 0);
            if (*p == 0)
                (void)lwps[pid];
        }
        closedir(d);
    }
}

pid_t
LiveProcess::getPID() const
{
    return pid;
}

void
LiveProcess::stopProcess()
{
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
        }
    });

    // Stop all LWPS.
    int i = 0;
    for (auto &lwp : lwps) {
        stop(lwp.first);
        i++;
    }
    if (verbose >= 2)
        *debug << "stopped process " << pid << "\n";
}

void
LiveProcess::resumeProcess()
{
    listThreads([] (const td_thrhandle_t *thr) {
        if (td_thr_dbresume(thr) == TD_NOCAPAB) {
            // this doesn't work in general, but it's ok, we'll suspend the LWP
            if (verbose >= 3)
                *debug << "can't resume thread "  << thr << "\n";
        }
    });

    for (auto &lwp : lwps)
        resume(lwp.first);

    resume(pid);
}

void
LiveProcess::stop(lwpid_t pid)
{
    auto &tcb = lwps[pid];
    if (tcb.stopCount++ != 0)
        return;

    gettimeofday(&tcb.stoppedAt, nullptr);
    if (ptrace(PT_ATTACH, pid, 0, 0) != 0) {
        *debug << "failed to stop LWP " << pid << ": ptrace failed: " << strerror(errno) << "\n";
        return;
    }

    int status;
    pid_t waitedpid = waitpid(pid, &status, pid == this->pid ? 0 : __WCLONE);
    if (waitedpid == -1)
        *debug << "failed to stop LWP " << pid << ": wait failed: " << strerror(errno) << "\n";
}
