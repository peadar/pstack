#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"
#include "libpstack/stringify.h"

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

LiveReader::LiveReader(Context &c, pid_t pid, const std::string &base) : FileReader(c, c.procname(pid, base)) {
   fileSize = std::numeric_limits<Reader::Off>::max();
}

Elf::Object::sptr
LiveProcess::executableImage() {
   return context.getImage(context.procname(getPID(), "exe"));
}

LiveProcess::LiveProcess(Context &context, Elf::Object::sptr &ex, pid_t pid_, bool alreadyStopped)
    : Process( context, ex, std::make_shared<CacheReader>(std::make_shared<LiveReader>(context, pid_, "mem")))
    , pid(pid_)
{
    (void)ps_getpid(this);
    if (alreadyStopped)
       stoppedLWPs[pid].stopCount = 1;
}

Reader::csptr LiveProcess::getAUXV() const {
    return std::make_shared<LiveReader>(context, pid, "auxv");
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
      if (context.verbose > 0)
         *context.debug << "not attempting to resume lwp " << lwpid << ", as it failed to stop\n";
      return;
   }
   if (ptrace(PT_DETACH, lwpid, caddr_t(1), 0) != 0 && context.debug != nullptr)
      *context.debug << "failed to detach from process " << lwpid << ": " << strerror(errno) << "\n";
   dynamic_cast<CacheReader&>(*io).flush();
   if (context.verbose >= 1) {
      timeval tv;
      gettimeofday(&tv, nullptr);
      intmax_t usecs = (tv.tv_sec - tcb.stoppedAt.tv_sec) * 1000000;
      usecs += tv.tv_usec;
      usecs -= tcb.stoppedAt.tv_usec;
      *context.debug << "resumed LWP " << lwpid << ": was stopped for " << std::dec <<
         usecs << " microseconds" << std::endl;
   }
}

void
LiveProcess::listLWPs(const std::function<void(lwpid_t)> &cb)
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
        std::string dirName = context.procname(pid, "task");
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
        if (lastStopCount != suspended.size() && (context.verbose >= 2 || lastStopCount != 1))
            *context.debug << "found " << suspended.size() - lastStopCount << " new LWPs after first " << lastStopCount << "\n";
    } while (lastStopCount != suspended.size());

    /*
     * Attempt to enumerate the threads and suspend with pthread_db. This will
     * probably just fail, but all the LWPs are suspended now, anyway.
     */
    listThreads([this] (const td_thrhandle_t *thr) {
        td_thrinfo_t info;
        td_thr_get_info(thr, &info);
        int suspendError = td_thr_dbsuspend(thr);
        if (suspendError != 0 && suspendError != TD_NOCAPAB)
            *context.debug << "can't suspend thread "  << thr << ": will suspend it's LWP " << info.ti_lid << "\n";
        });

    if (context.verbose >= 2)
        *context.debug << "stopped process " << pid << "\n";
}

void
LiveProcess::resumeProcess()
{
    // this doesn't work on Linux nptl, but it's ok, we'll resume the LWP below.
    listThreads([this] (const td_thrhandle_t *thr) {
        int rc = td_thr_dbresume(thr);
        if (rc != 0 && rc != TD_NOCAPAB)
            *context.debug << "can't resume thread "  << thr << " (will resume it's LWP)\n";
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
      *context.debug << "failed to stop LWP " << tid << ": ptrace failed: " << strerror(errno) << "\n";
      return;
   }
   tcb.ptraceErr = 0;

   int status = 0;
   pid_t waitedpid = waitpid(tid, &status, tid == this->pid ? 0 : __WCLONE);
   if (waitedpid == -1)
      *context.debug << "failed to stop LWP " << tid << ": wait failed: " << strerror(errno) << "\n";
   else if (context.verbose >= 1)
      *context.debug << "suspend LWP " << tid << std::endl;
}

// Parse [s]maps for this pid. We use "smaps" just for vmflags for now.
std::vector<AddressRange>
LiveProcess::addressSpace() const { return procAddressSpace(context.procname(pid, "smaps")); }

template < typename Separator >
static std::string_view nextTok( std::string_view &total, Separator sep ) {
   auto startPos = total.find_first_not_of(' '); // skip whitespace at the start.
   size_t sepPos = total.find_first_of( sep, startPos );
   std::string_view res;
   if ( sepPos == std::string::npos ) {
      res = total;
      total = "";
   } else {
      res = total.substr( 0, sepPos );
      total = total.substr( sepPos + 1 );
   }
   return res;
}

static uintmax_t hex2int(std::string_view strv) {
   // This is basically strtoul(strv, 0, 16), but stroul won't take a
   // string_view, and its costly to create a string from this substring of the
   // processed line.
   uintmax_t val = 0;
   for (auto c : strv) {
      val *= 16;
      if (c >= '0' && c <= '9')
         val += c - '0';
      else if (c >= 'a' && c <= 'f')
         val += c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
         val += c - 'A' + 10;
      else
         throw std::logic_error("unexpected character in hex string");
   }
   return val;
}

std::vector<AddressRange>
Process::procAddressSpace(const std::string &fn) {
    std::vector<AddressRange> rv;
    // there can be many mappings, and we don't call this very often, so
    // pre-allocate the space we need.
    rv.reserve(10240);

    std::string buf;
    buf.reserve( 1024 );
    std::ifstream input{fn};
    if ( !input.is_open() || !input.good()){
         throw ( Exception() << "unable to open smaps file: " << strerror(errno) );
    }
    while (input && input.peek() != EOF) {
       // We could just use operator>> to stream each field of the line to the
       // relevant fields, but it is ridiculously slow, I Think mostly because
       // of the use of std::hex invoking std::use_facet, which uses dynamic
       // casts. So, instead, parse out the line the hard way. This first line
       // includes details of the address range covered, and some basic
       // details. The /proc/<pid>/maps file includes just these lines.
       std::getline( input, buf );
       std::string_view remains{ buf };

       rv.emplace_back();
       AddressRange &range = rv.back();
       range.start = hex2int(nextTok( remains, '-' ));
       range.end = hex2int(nextTok( remains, ' ' ));

       std::string_view  perms = nextTok( remains, ' ' );

       static const std::unordered_map<char, AddressRange::Permission> flagmap {
           { 'r', AddressRange::Permission::read },
           { 'w', AddressRange::Permission::write },
           { 'x', AddressRange::Permission::exec },
           { 'p', AddressRange::Permission::priv },
           { 's', AddressRange::Permission::shared },
       };
       for (auto c : perms)
           if (c != '-')
               range.permissions.insert(flagmap.at(c));

       range.offset = hex2int(nextTok( remains, ' ' ));

       auto &backing = range.backing;
       backing.major = hex2int(nextTok( remains, ':' ));
       backing.minor = hex2int(nextTok( remains, ' ' ));
       backing.inode = hex2int(nextTok( remains, ' ' ));

       size_t trim = remains.find_first_not_of(" ");
       if ( trim != std::string::npos ) {
          backing.path = remains.substr( trim );
       } else {
          backing.path = "<anon>";
       }

       // Now process the attribute lines under the details of the range. These
       // are only present for /proc/<pid>/smaps.

       while (isupper(input.peek())) {
          std::getline(input, buf);
          std::string_view lineview { buf };
          auto key = nextTok( lineview, ':' );
          if (key == "VmFlags") {
             for (;;) {
                auto tok = nextTok( lineview, ' ' );
                if (tok == "")
                   break;
                auto flag = AddressRange::vmflag(tok);
                if (flag)
                   range.vmflags.insert( *flag );
             }
          }
       }
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

std::optional<siginfo_t>
LiveProcess::getSignalInfo() const
{
   return std::nullopt;
}

std::optional<AddressRange::VmFlag> AddressRange::vmflag(std::string_view sv) {
    static const std::unordered_map<std::string_view, AddressRange::VmFlag> flagmap {
       { "rd", VmFlag::readable },
       { "wr", VmFlag::writeable },
       { "ex", VmFlag::executable },
       { "sh", VmFlag::shared },
       { "mr", VmFlag::may_read },
       { "mw", VmFlag::may_write },
       { "me", VmFlag::may_execute },
       { "ms", VmFlag::may_share },
       { "gd", VmFlag::stack_grows_down },
       { "pf", VmFlag::pure_pfn_range },
       { "dw", VmFlag::disabled_write },
       { "lo", VmFlag::pages_locked },
       { "io", VmFlag::memory_mapped_io },
       { "sr", VmFlag::sequential_read_advised },
       { "rr", VmFlag::random_read_advised },
       { "dc", VmFlag::dont_copy_on_fork },
       { "de", VmFlag::dont_expand_on_remap },
       { "ac", VmFlag::accountable },
       { "nr", VmFlag::swap_not_reserved },
       { "ht", VmFlag::huge_tlb_pages },
       { "sf", VmFlag::synchronous_page_fault },
       { "ar", VmFlag::architecture_specific },
       { "wf", VmFlag::wipe_on_fork },
       { "dd", VmFlag::dont_dump },
       { "sd", VmFlag::soft_dirty },
       { "mm", VmFlag::mixed_map },
       { "hg", VmFlag::huge_page_advised },
       { "nh", VmFlag::no_huge_page_advised },
       { "mg", VmFlag::mergeable_advised },
       { "bt", VmFlag::arm64_BTI_guarded_page },
       { "mt", VmFlag::arm64_MTE_allocation_tags },
       { "um", VmFlag::userfaultfd_missing_tracking },
       { "uw", VmFlag::userfaultfd_wr_protect_tracking },
       { "ss", VmFlag::shadow_stack },
       { "sl", VmFlag::sealed },
    };
    auto it = flagmap.find( sv );
    if (it != flagmap.end()) {
       return it->second;
    }
    return std::nullopt;
}

}
