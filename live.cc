#include "procinfo.h"
#include <err.h>

#include <iostream>
#include <limits.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <wait.h>

std::string
LiveReader::procname(pid_t pid, std::string base)
{
    std::ostringstream ss;
    ss << "/proc/" << pid << "/" << base;
    return ss.str();
}

LiveProcess::LiveProcess(std::shared_ptr<ElfObject> ex, pid_t pid_)
    : Process(ex ? ex : std::make_shared<ElfObject>(std::make_shared<LiveReader>(pid_, "exe"))
        , std::make_shared<LiveReader>(pid_, "mem"))
    , pid(pid_)
    , stopCount(0)
{

}

void
LiveProcess::load()
{
    char path[PATH_MAX];
    snprintf(path, sizeof path, "/proc/%d/auxv", pid);
    int fd = open(path, O_RDONLY);
    if (fd == -1)
        throw Exception() << "failed to open " << path << ": " << strerror(errno);
    char buf[4096];
    ssize_t rc = ::read(fd, buf, sizeof buf);
    close(fd);
    if (rc == -1)
        throw Exception() << "failed to read 4k from " << path;
    processAUXV(buf, rc);
    Process::load();
}

bool
LiveProcess::getRegs(lwpid_t pid, CoreRegisters *reg) const
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
    return ptrace(__ptrace_request(PTRACE_GETREGS), pid, 0, reg) != -1;
#endif
}

void
LiveProcess::resume(lwpid_t pid)
{
    auto &tcb = stoppedLwps[pid];
    if (tcb.state == running)
        return;

    kill(pid, SIGCONT);
    if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
        std::clog << "failed to detach from process " << pid << ": " << strerror(errno);

    tcb.state = running;
    if (debug && --stopCount == 0) {
        timeval tv;
        gettimeofday(&tv, 0);
        long long secs = (tv.tv_sec - start.tv_sec) * 1000000;
        secs += tv.tv_usec;
        secs -= start.tv_usec;
        *debug << "child was stopped for " << std::dec << secs << " microseconds" << std::endl;
    }
}


void
LiveProcess::stopProcess()
{
    stop(pid);
    // suspend everything quickly.
    listThreads(
        [this] (const td_thrhandle_t *thr) -> void {
            if (td_thr_dbsuspend(thr) == TD_NOCAPAB) {
                /* 
                 * This doesn't actually work under linux: just add the LWP
                 * to the list of stopped lwps.
                 */
                td_thrinfo_t info;
                td_thr_get_info(thr, &info);
                lwps.insert(info.ti_lid);
            }});

    for (auto lwp : lwps)
        stop(lwp);
}

void
LiveProcess::resumeProcess()
{
    listThreads([](const td_thrhandle_t *thr) { td_thr_dbresume(thr); }); 
    for (auto lwp : lwps)
        resume(lwp);
    resume(pid);
}

void
LiveProcess::stop(lwpid_t pid)
{
    auto &tcb = stoppedLwps[pid];
    if (tcb.state == stopped)
        return;

    if (stopCount++ == 0 && debug) {
        *debug << "stopping child" << std::endl;
        gettimeofday(&start, 0);
    }

    if (ptrace(PT_ATTACH, pid, 0, 0) == 0) {
        int status;
        pid_t waitedpid = waitpid(pid, &status, pid == this->pid ? 0 : __WCLONE);
        if (waitedpid != -1) {
            tcb.state = stopped;
            return;
        }
        if (debug) *debug << "wait failed: " << strerror(errno) << "\n";
        return;
    }
    if (debug) *debug << "ptrace failed: " << strerror(errno) << "\n";
}
