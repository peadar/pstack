#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"
#include "libpstack/stringify.h"
#include "libpstack/global.h"
#include "libpstack/fs.h"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <wait.h>

#include <climits>
#include <iostream>
#include <utility>
#include <fstream>

namespace pstack::Procman {
std::string
procname(pid_t pid, const std::string &base)
{
    return linkResolve(stringify("/proc/", pid, "/", base));
}

LiveReader::LiveReader(pid_t pid, const std::string &base)
   : FileReader(procname(pid, base), std::numeric_limits<Reader::Off>::max()) {}

LiveProcess::LiveProcess(Elf::Object::sptr &ex, pid_t pid_,
            const PstackOptions &options, Dwarf::ImageCache &imageCache, bool alreadyStopped)
    : Process(
            ex ? ex : imageCache.getImageForName(procname(pid_, "exe")),
            std::make_shared<CacheReader>(std::make_shared<LiveReader>(pid_, "mem")),
            options, imageCache)
    , pid(pid_)
{
    (void)ps_getpid(this);
    if (alreadyStopped)
       lwps[pid].stopCount = 1;
}

Reader::csptr LiveProcess::getAUXV() const {
    return std::make_shared<LiveReader>(pid, "auxv");
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
    int rc = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
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
    if (tcb.ptraceErr != 0) {
       if (verbose)
          *debug << "not attempting to resume lwp " << pid << ", as it failed to stop\n";
       return;
    }
    if (ptrace(PT_DETACH, pid, caddr_t(1), 0) != 0)
        std::clog << "failed to detach from process " << pid << ": " << strerror(errno) << "\n";
    dynamic_cast<CacheReader&>(*io).flush();
    if (verbose >= 1) {
        timeval tv;
        gettimeofday(&tv, nullptr);
        intmax_t usecs = (tv.tv_sec - tcb.stoppedAt.tv_sec) * 1000000;
        usecs += tv.tv_usec;
        usecs -= tcb.stoppedAt.tv_usec;
        *debug << "resumed LWP " << pid << ": was stopped for " << std::dec <<
           usecs << " microseconds" << std::endl;
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
     * Stop all LWPs/kernel tasks. Do this before we stop the threads. Stopping the
     * threads with thread_db actually just returns an error in linux, but
     * stopping everything here ensures that we are not racing the process
     * threads to read the thread list later.
     */
    for (auto &lwp : lwps)
        stop(lwp.first);

    /*
     * Attempt to enumerate the threads and suspend with pthread_db. This will
     * probably just fail, but all the LWPs are suspended now, anyway.
     */
    listThreads([this] (const td_thrhandle_t *thr) {
        td_thrinfo_t info;
        td_thr_get_info(thr, &info);
        (void)lwps[info.ti_lid]; // make sure we have the LWP
        if (td_thr_dbsuspend(thr) == TD_NOCAPAB) {
            if (verbose >= 3)
                *debug << "can't suspend thread "  << thr
                       << ": will suspend it's LWP " << info.ti_lid << "\n";
        }
    });

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
                *debug << "can't resume thread "  << thr << " (will resume it's LWP)\n";
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
        tcb.ptraceErr = errno;
        *debug << "failed to stop LWP " << pid << ": ptrace failed: " << strerror(errno) << "\n";
        return;
    }
    tcb.ptraceErr = 0;

    int status;
    pid_t waitedpid = waitpid(pid, &status, pid == this->pid ? 0 : __WCLONE);
    if (waitedpid == -1)
        *debug << "failed to stop LWP " << pid << ": wait failed: " << strerror(errno) << "\n";
    else if (verbose >= 1)
        *debug << "suspend LWP " << pid << std::endl;
}

std::vector<AddressRange>
LiveProcess::addressSpace() const { return procAddressSpace(procname(pid, "maps")); }

std::vector<AddressRange>
Process::procAddressSpace(const std::string &fn) {
    std::vector<AddressRange> rv;
    std::ifstream input(fn);
    for (;;) {
       std::string line;
       std::getline(input, line);
       std::istringstream lineStream(line);

       uintptr_t start, end;
       off_t offset;
       int major, minor;
       unsigned long inode;
       std::string perms, path;
       char colon, minus;
       lineStream >> std::hex >> start >> minus >> end >> perms >> offset >> major >> colon >> minor >> inode >> path;
       if (input.eof() || !input.good())
          break;
       std::set<AddressRange::Flags> flags;
       for (auto c : perms) {
           static const std::map<char, AddressRange::Flags> flagmap {
               { 'r', AddressRange::Flags::read },
               { 'w', AddressRange::Flags::write },
               { 'x', AddressRange::Flags::exec },
               { 'p', AddressRange::Flags::priv },
               { 's', AddressRange::Flags::shared },
           };
           if (c != '-')
               flags.insert(flagmap.at(c));
       }
       rv.push_back({start, end, end, offset, {major, minor, inode, path}, flags });
    }
    return rv;
}


bool
LiveProcess::loadSharedObjectsFromFileNote()
{
    // In theory we can implement this by grovelling in /proc/<pid>/maps, but
    // it mostly exists for truncated core files, so don't bother now.
    return false;
}
}
