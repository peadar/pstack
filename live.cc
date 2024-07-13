#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"
#include "libpstack/stringify.h"
#include "libpstack/global.h"
#include "libpstack/fs.h"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <wait.h>
#include <iostream>
#include <utility>
#include <fstream>

namespace pstack::Procman {
std::string
procname(pid_t pid, const std::string &base)
{
    return linkResolve(stringify("/proc/", pid, "/", base));
}

LiveReader::LiveReader(pid_t pid, const std::string &base) : FileReader(procname(pid, base)) {
   fileSize = std::numeric_limits<Reader::Off>::max();
}

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
       stoppedLWPs[pid].stopCount = 1;
}

Reader::csptr LiveProcess::getAUXV() const {
    return std::make_shared<LiveReader>(pid, "auxv");
}

size_t
LiveProcess::getRegs(lwpid_t lwpid, int code, size_t sz, void *reg) {
    StopLWP here( this, lwpid );
    iovec iov { .iov_base = reg, .iov_len = sz };
    int rc = ptrace(PTRACE_GETREGSET, lwpid, code, &iov);
    return rc == 0 ? iov.iov_len : 0;
}

void
LiveProcess::resume(lwpid_t lwpid) {
   auto tcbi = stoppedLWPs.find(lwpid);
   if (tcbi == stoppedLWPs.end())
      return;
   auto &tcb = tcbi->second;
   if (--tcb.stopCount != 0)
      return;
   if (tcb.ptraceErr != 0) {
      if (verbose > 0)
         *debug << "not attempting to resume lwp " << lwpid << ", as it failed to stop\n";
      return;
   }
   if (ptrace(PT_DETACH, lwpid, caddr_t(1), 0) != 0 && debug != nullptr)
      *debug << "failed to detach from process " << lwpid << ": " << strerror(errno) << "\n";
   dynamic_cast<CacheReader&>(*io).flush();
   if (verbose >= 1) {
      timeval tv;
      gettimeofday(&tv, nullptr);
      intmax_t usecs = (tv.tv_sec - tcb.stoppedAt.tv_sec) * 1000000;
      usecs += tv.tv_usec;
      usecs -= tcb.stoppedAt.tv_usec;
      *debug << "resumed LWP " << lwpid << ": was stopped for " << std::dec <<
         usecs << " microseconds" << std::endl;
   }
}

void
LiveProcess::listLWPs(std::function<void(lwpid_t)> cb)
{
   for (auto &lwp : stoppedLWPs)
      if (lwp.second.ptraceErr == 0)
         cb(lwp.first);
}

pid_t
LiveProcess::getPID() const
{
    return pid;
}

LiveProcess::~LiveProcess() {
   for (auto &lwp : stoppedLWPs) {
      if (lwp.second.stopCount > 0) {
         lwp.second.stopCount = 1; // remove all soft "stops".
         resume(lwp.first);
      }
   }
};

void
LiveProcess::stopProcess()
{
    // suspend the main process itself first.
    // XXX: Note this can actually fail if the main thread exits before the
    // remaining tasks.  Other things also fail in that case - eg, opening
    // stuff from /proc/pid/fd, etc. Really those operations should use
    // /proc/<pid>/task/<tid> of a task we have suspended, rather than the main
    // process
    std::set<lwpid_t> suspended;
    stop(pid);
    suspended.insert(pid);

    /*
     * Stop all remaining LWPs/kernel tasks. Do this before we stop the
     * threads. Stopping the threads with thread_db actually just returns an
     * error in linux, but stopping everything here ensures that we are not
     * racing the process threads to read the thread list later.
     */
    size_t lastStopCount;
    do {
        lastStopCount = suspended.size();
        std::string dirName = procname(pid, "task");
        DIR *d = opendir(dirName.c_str());
        if (d != nullptr) {
            for (dirent *de; (de = readdir(d)) != nullptr; ) {
                char *p;
                lwpid_t tid = strtol(de->d_name, &p, 0);
                if (*p == 0) {
                    auto [_, isnew ] = suspended.insert(tid);
                    if (isnew)
                        stop(tid);
                }
            }
        }
        closedir(d);
        // if we found any threads, log it as debug. If we went around more than once, always log.
        if (lastStopCount != suspended.size() && (verbose >= 2 || lastStopCount != 1))
            *debug << "found " << suspended.size() - lastStopCount << " new LWPs after first " << lastStopCount << "\n";
    } while (lastStopCount != suspended.size());

    /*
     * Attempt to enumerate the threads and suspend with pthread_db. This will
     * probably just fail, but all the LWPs are suspended now, anyway.
     */
    listThreads([] (const td_thrhandle_t *thr) {
        td_thrinfo_t info;
        td_thr_get_info(thr, &info);
        int suspendError = td_thr_dbsuspend(thr);
        if (suspendError != 0 && suspendError != TD_NOCAPAB)
            *debug << "can't suspend thread "  << thr << ": will suspend it's LWP " << info.ti_lid << "\n";
        });

    if (verbose >= 2)
        *debug << "stopped process " << pid << "\n";
}

void
LiveProcess::resumeProcess()
{
    // this doesn't work on Linux nptl, but it's ok, we'll resume the LWP below.
    listThreads([] (const td_thrhandle_t *thr) {
        int rc = td_thr_dbresume(thr);
        if (rc != 0 && rc != TD_NOCAPAB)
            *debug << "can't resume thread "  << thr << " (will resume it's LWP)\n";
    });

    for (auto &lwp : stoppedLWPs)
        resume(lwp.first);

    // C++17: remove all LWPs that are now resumed)
    for (auto it = stoppedLWPs.begin(); it != stoppedLWPs.end(); )
        if (it->second.stopCount == 0)
            it = stoppedLWPs.erase(it);
        else
            ++it;
    /* C++20:
       std::erase_if(stoppedLWPs, [](auto &&entry) { return entry.stopCount == 0; } );
       */
}

void
LiveProcess::stop(lwpid_t tid) {
   auto &tcb = stoppedLWPs[tid];
   if (tcb.stopCount++ != 0)
      return;

   gettimeofday(&tcb.stoppedAt, nullptr);
   if (ptrace(PT_ATTACH, tid, 0, 0) != 0) {
      tcb.ptraceErr = errno;
      *debug << "failed to stop LWP " << tid << ": ptrace failed: " << strerror(errno) << "\n";
      return;
   }
   tcb.ptraceErr = 0;

   int status = 0;
   pid_t waitedpid = waitpid(tid, &status, tid == this->pid ? 0 : __WCLONE);
   if (waitedpid == -1)
      *debug << "failed to stop LWP " << tid << ": wait failed: " << strerror(errno) << "\n";
   else if (verbose >= 1)
      *debug << "suspend LWP " << tid << std::endl;
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
       ino_t inode;
       std::string perms, path;
       char colon, minus;
       lineStream >> std::hex >> start >> minus >> end >> perms >> offset >>
          major >> colon >> minor >> std::dec >> inode >> path;
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
