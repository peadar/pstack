#include "procinfo.h"
#include <err.h>

#include <iostream>
#include <limits.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <wait.h>

void
LiveProcess::load()
{
#ifdef __linux__
    char path[PATH_MAX];
    snprintf(path, sizeof path, "/proc/%d/auxv", pid);
    int fd = open(path, O_RDONLY);
    if (fd == -1)
        throw Exception() << "failed to open " << path;
    char buf[4096];
    ssize_t rc = ::read(fd, buf, sizeof buf);
    close(fd);
    if (rc == -1)
        throw Exception() << "failed to read 4k from " << path;
    processAUXV(buf, rc);
#endif
    Process::load();
}


std::string
LiveReader::memname(pid_t pid)
{
    std::ostringstream ss;
    ss << "/proc/" << pid << "/mem";
    return ss.str();
}

LiveProcess::LiveProcess(ElfObject *ex, pid_t pid_, std::ostream *debug)
    : Process(ex, liveIO, debug)
    , pid(pid_)
    , liveIO(pid_)
{
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

    auto &tcb = lwps[pid];
    if (tcb.state == running)
        return;

    kill(pid, SIGCONT);
    if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
        std::clog << "failed to detach from process " << pid << ": " << strerror(errno);
}

void
LiveProcess::stop(lwpid_t pid)
{
    int status;

    auto &tcb = lwps[pid];
    if (tcb.state == stopped)
        return;

    std::clog << "attach to " << pid << "... ";
    if (ptrace(PT_ATTACH, pid, 0, 0) == 0) {
        pid_t waitedpid = waitpid(pid, &status, pid == this->pid ? 0 : __WCLONE);
        if (waitedpid != -1) {
            tcb.state = stopped;
            std::clog << "success\n";
            return;
        }
        std::clog << "wait failed: " << strerror(errno) << "\n";
        return;
    }
    std::clog << "ptrace failed: " << strerror(errno) << "\n";
}