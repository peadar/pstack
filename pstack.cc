#include "libpstack/dwarf.h"
#include "libpstack/flags.h"
#include "libpstack/global.h"
#include "libpstack/proc.h"
#include "libpstack/fs.h"
#include "libpstack/ps_callback.h"
#if defined(WITH_PYTHON2) || defined(WITH_PYTHON3)
#define WITH_PYTHON
#include "libpstack/python.h"
#endif

#include <sys/types.h>
#include <sys/signal.h>
#include <sys/wait.h>

#include <sysexits.h>
#include <unistd.h>

#include <csignal>
#include <algorithm>
#include <fstream>
#include <iostream>

#define XSTR(a) #a
#define STR(a) XSTR(a)

namespace {
using namespace pstack;

bool doJson = false;
volatile bool interrupted = false;

void
pstack(Procman::Process &proc)
{
    const auto &threadStacks = proc.getStacks();
    auto &os = *proc.options.output;
    if (doJson) {
        os << json(threadStacks, const_cast<const Procman::Process*>(&proc));
    } else {
        os << "process: " << *proc.io << "\n";
        for (auto &s : threadStacks) {
            proc.dumpStackText(os, s);
            os << std::endl;
        }
    }
}

// This is mostly for testing. We start the process, and run pstack when we see
// a signal that is likely to terminate the process, then kill it. This allows
// us to reliably run pstack on a process that will abort or segfault, and
// doesn't require a readable core file.
int
startChild(Elf::Object::sptr exe, const std::string &cmd, const PstackOptions &options, Dwarf::ImageCache &ic) {
   std::vector<std::string> args;
   for (size_t off = 0;;) {
      auto pos = cmd.find(' ', off);
      if (pos == std::string::npos) {
         args.push_back(cmd.substr(off));
         break;
      } else {
         args.push_back(cmd.substr(off, pos));
         off = pos + 1;
      }
   }

   int rc, status;
   pid_t pid = fork();
   switch (pid) {
      case 0: {
         rc = ptrace(PTRACE_TRACEME, 0, 0, 0);
         assert(rc == 0);
         std::vector<const char *> sysargs;
         std::transform(args.begin(), args.end(), std::back_inserter(sysargs),
                        [] (const std::string &arg) { return arg.c_str(); });
         sysargs.push_back(nullptr);
         execvp(sysargs[0], (char **)&sysargs[0]);
         if (verbose > 2)
             *debug << getpid() << " execvp failed: " << strerror(errno) << "\n";
         // child
         break;
      }
      case -1:
         // error
         return -1;
      default:
         std::shared_ptr<Procman::Process> p;
         char statusBuf[PATH_MAX];
         snprintf(statusBuf, sizeof statusBuf, "/proc/%d/status", pid);
         struct closer { void operator()(FILE *f){ fclose(f); }};
         std::unique_ptr<FILE, closer> statusFile { fopen(statusBuf, "r") };
         assert(statusFile.get());

         for (;;) {
            if (verbose > 2)
               *debug << getpid() << " waiting...\n";
            rc = wait(&status);
            if (rc != pid) {
               if (verbose > 2)
                  *debug << getpid() << "... wait failed: " << strerror(errno) << "\n";
               break;
            }
            if (verbose > 2)
               *debug << getpid() << "... done - rc=" << rc << ", status=" << Procman::WaitStatus(status) << "\n";

            if (WIFSTOPPED(status)) {
               // Read the content of the process's SigIgn and SigCgt info from procfs.
               fflush(statusFile.get());
               fseek(statusFile.get(), 0, SEEK_SET);
               char line[PATH_MAX];
               uint64_t sigblk = -1, sigign = -1, sigcgt = -1;
               while (fgets(line, sizeof line, statusFile.get()) != NULL) {
                  if (strncmp(line, "SigBlk:\t", 8) == 0)
                     sigblk = strtoull(line + 8, 0, 16);
                  else if (strncmp(line, "SigCgt:\t", 8) == 0)
                     sigcgt = strtoull(line + 8, 0, 16);
                  else if (strncmp(line, "SigIgn:\t", 8) == 0)
                     sigign = strtoull(line + 8, 0, 16);
               }
               unsigned long handledSigs = sigblk | sigcgt | sigign;
               handledSigs |= 1 << (SIGTRAP - 1);
               int stopsig = WSTOPSIG(status);
               int contsig = stopsig == SIGSTOP || stopsig == SIGTRAP ? 0 : stopsig;
               if (((1 << (stopsig -1)) & handledSigs) == 0) {
                  p = std::make_shared<Procman::LiveProcess>(exe, pid, options, ic, true);
                  p->load();
                  pstack(*p);
                  rc = ptrace(PTRACE_KILL, pid, 0, contsig);
               } else {
                  rc = ptrace(PTRACE_CONT, pid, 0, contsig);
               }
               if (rc == -1)
                  *debug << getpid() << " ptrace failed to kill/continue - " << strerror(errno) << "\n";
               assert(rc == 0);
               if (verbose > 2)
                  *debug << getpid() << "..done\n";
            }
            else {
               return 0;
            }
         }
         break;
   }
   return 0;
}


#ifdef WITH_PYTHON
template<int V> void doPy(Procman::Process &proc, bool showModules, const PyInterpInfo &info) {
    Procman::StopProcess here(&proc);
    PythonPrinter<V> printer(proc, *proc.options.output, info);
    if (!printer.interpFound())
        throw Exception() << "no python interpreter found";
    printer.printInterpreters(showModules);
}

/**
 * @brief Given a process, tries to print the Python strack trace of it.
 * If the process wasn't a Python process, returns false.
 * True on successful printing of Python stack trace
 * 
 * @param proc          The process
 * @param o             The stream to which to print the otutput
 * @param options       Options
 * @param showModules   Whether to show modules
 * @return              boolean of whether the process was a Python process or not
 */
bool pystack(Procman::Process &proc, bool showModules) {
    PyInterpInfo info = getPyInterpInfo(proc);

    if (info.libpython == nullptr) // not a python process or python interpreter not found
        return false;

    if (info.versionHex < V2HEX(3, 0)) { // Python 2.x
#ifdef WITH_PYTHON2
        doPy<2>(proc, showModules, info);
#else
        throw (Exception() << "no support for discovered python 2 interpreter");
#endif
    } else { // Python 3.x
#ifdef WITH_PYTHON3
        doPy<3>(proc, showModules, info);
#else
        throw (Exception() << "no support for discovered python 3 interpreter");
#endif
    }
    return true;
}
#endif

int
usage(std::ostream &os, const char *name, const Flags &options)
{
     os <<
"usage: " << name << " <[ exe ] <PID | core> >+\n"
"\n"
"print a stack trace of PID or core. If specified, assume image was created from\n"
" execing `exe`, otherwise, the executable is inferred from the process or core\n"
"\n"
"available options:\n" << options <<  "\n";
     return EX_USAGE;
}

int
emain(int argc, char **argv, Dwarf::ImageCache &imageCache)
{
    double sleepTime = 0.0;
    PstackOptions options;
    std::ofstream out;

#if defined(WITH_PYTHON)
    bool doPython = false;
    bool pythonModules = false;
#endif
    std::vector<std::string> btLogs;
    std::string execName;
    bool printAllStacks = false;
    int exitCode = -1; // used for options that exit immediately to signal exit.
    std::string subprocessCmd;

    Flags flags;
    flags
    .add("replace-path",
            'F',
            "from:to",
            "replace `from` with `to` in paths when finding shared libraries",
            [&](const char *arg) {
                auto sep = strchr(arg, ':');
                if (sep == 0)
                    usage(std::cerr, argv[0], flags);
                pathReplacements.push_back(std::make_pair(
                            std::string(arg, sep - arg), std::string(sep + 1))); })

    .add("debug-dir",
            'g',
            "directory",
            "extra location to find debug files for binaries and shared libraries",
            [&](const char *arg) { Elf::globalDebugDirectories.push_back(arg); })

    .add("constant",
            'b',
            "delay",
            "repeat pstack, with `delay` seconds between each iteration (can be non-integer)",
            Flags::set(sleepTime))

    .add("elf-dump",
            'd',
            "ELF file",
            "dump details of an ELF image in JSON and exit",
            [&](const char *arg) {
                *options.output << json(Elf::Object(imageCache, loadFile(arg)));
                exitCode = 0; })

    .add("dwarf-dump",
            'D',
            "ELF file",
            "dump details of DWARF information in an ELF image in JSON and exit",
            [&](const char *arg) {
                auto dumpobj = std::make_shared<Elf::Object>(imageCache, loadFile(arg));
                auto di = std::make_shared<Dwarf::Info>(dumpobj, imageCache);
                *options.output << json(*di);
                exitCode = 0; })

    .add("depth",
            'r',
            "depth",
            "max depth when printing python structures",
            Flags::set(options.maxdepth))

    .add("max-frames",
            'M',
            "max frames",
            "maximum number of stack frames to print for a thread",
            Flags::set(options.maxdepth))

    .add("help",
            'h',
            "generate this help message",
            [&]() { exitCode = usage(std::cout, argv[0], flags); })

    .add("args",
            'a',
            "attempt to show the value of arguments to functions",
            Flags::setf(options.doargs))

    .add("json",
            'j',
            "use JSON output rather than plaintext",
            Flags::setf(doJson))

    .add("no-src",
            's',
            "don't include source info",
            Flags::setf(options.nosrc))

    .add("verbose",
            'v',
            "more debugging data. Can be repeated",
            [&]() { ++verbose; })

    .add("no-threaddb",
            't',
            "don't use the thread_db functions to enumerate pthreads (just uses LWPs)",
            Flags::setf(options.nothreaddb))

    .add("all",
            'A',
            "show both python and DWARF (C/C++/go/rust) stack traces",
            Flags::setf(printAllStacks))

    .add("no-ext-debug",
            'n',
            "don't load external debugging information when processing",
            Flags::setf(Elf::noExtDebug))

    .add("version",
            'V',
            "dump version and exit",
            [&]() {
               std::clog << STR(VERSION) << "\n";
               exitCode = 0; })

#ifdef WITH_PYTHON
    .add("python-modules",
            'm',
            "print contents of all python modules when tracing",
            Flags::setf(pythonModules))

    .add("python",
            'p',
            "print python stack traces",
            Flags::setf(doPython))

    .add("locals",
            'l',
            "print local variables (just python for now)",
            Flags::setf(options.dolocals))
#endif
    .add("from-log",
            'L',
            "log-file",
            "print stack trace given log file including instruction pointers",
            [&](const char *log) {
               btLogs.push_back(log);
            })
    .add("executable",
          'e',
          "executable",
          "executable to use by default", [&](const char *opt) { execName = opt; })
    .add("command",
          'x',
          "command line",
          "execute command line as subprocess, trace when it receives a signal", Flags::set<std::string>(subprocessCmd))
    .add("output",
          'o',
          "output file",
          "write output to <output file> instead of stdout", [&options, &out] (const char *opt) {
             out = std::ofstream(opt, std::ofstream::out|std::ofstream::trunc);
             options.output = &out;
          })
    .parse(argc, argv);

    if (exitCode != -1)
        return exitCode;

    // any instance of a non-core ELF image will override default behaviour of
    // discovering the executable
    Elf::Object::sptr exec;
    if (execName != "")
         exec = imageCache.getImageForName(execName);

    if (subprocessCmd != "") {
        // create a new process and trace it.
        startChild(exec, subprocessCmd, options, imageCache);
        return 0;
    }

    if (optind == argc && btLogs.empty())
        return usage(std::cerr, argv[0], flags);

    auto doStack = [=, &options] (Procman::Process &proc) {
        while (!interrupted) {
#if defined(WITH_PYTHON)
            if (doPython || printAllStacks) {
                bool isPythonProcess = pystack(proc, pythonModules);
                // error if -p but not python process
                if (doPython && !isPythonProcess)
                    throw Exception() << "Couldn't find a Python interpreter";
            }
            if (!doPython)
#endif
            {
                pstack(proc);
            }
            if (sleepTime != 0.0)
                usleep(sleepTime * 1000000);
            else
                break;
        }
    };
    if (!btLogs.empty()) {
        Procman::LogProcess lp{exec, btLogs, options, imageCache};
       lp.load();
       doStack(lp);
    } else {
        for (int i = optind; i < argc; i++) {
            try {
                auto process = Procman::Process::load(exec, argv[i], options, imageCache); // this calls the load() instance member.
                if (process == nullptr)
                    exec = imageCache.getImageForName(argv[i]);
                else
                    doStack(*process);
            } catch (const std::exception &e) {
                std::cerr << "trace of " << argv[i] << " failed: " << e.what() << "\n";
            }
        }
    }
    return 0;
}
}

int
main(int argc, char **argv)
{
    try {
        Dwarf::ImageCache imageCache;
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = [](int) { interrupted = true; };
        // Only interrupt cleanly once. Then just terminate, in case we're stuck in a loop
        sa.sa_flags = SA_RESETHAND;
        sigaction(SIGINT, &sa, nullptr);
        emain(argc, argv, imageCache);
        exit(0);
    }
    catch (std::exception &ex) {
        std::clog << "error: " << ex.what() << std::endl;
        return EX_SOFTWARE;
    }
}
