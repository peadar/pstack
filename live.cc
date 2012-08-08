#include "procinfo.h"
#include <iostream>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <err.h>
#include <wait.h>

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

LiveProcess::LiveProcess(Reader &ex, pid_t pid_)
    : Process(ex)
    , pid(pid_)
{
    char buf[PATH_MAX];
    snprintf(buf, sizeof buf, "/proc/%d/mem", pid);
    procMem = fopen(buf, "r");
    if (procMem == 0)
        throw 999;
}

void
LiveProcess::read(off_t remoteAddr, size_t size, char *ptr) const
{
    if (fseek(procMem, remoteAddr, SEEK_SET) == -1)
        throw 999;
    if (fread(ptr, size, 1, procMem) != 1)
        throw 999;

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
LiveProcess::resume(pid_t pid) const
{
    if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
        warn("failed to detach from process %d", pid);
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


