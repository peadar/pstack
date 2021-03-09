#include "libpstack/dwarf.h"
#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"
#if defined(WITH_PYTHON2) || defined(WITH_PYTHON3)
#define WITH_PYTHON
#include "libpstack/python.h"
#endif

#include <sys/types.h>
#include <sys/signal.h>

#include <sysexits.h>
#include <unistd.h>

#include <csignal>

#include <iostream>
#include <set>

#define XSTR(a) #a
#define STR(a) XSTR(a)
extern std::ostream & operator << (std::ostream &os, const JSON<ThreadStack, Process *> &jt);

namespace {
bool doJson = false;
volatile bool interrupted = false;

int usage(const char *);
std::ostream &
pstack(Process &proc, std::ostream &os, const PstackOptions &options)
{
    // get its back trace.
    std::list<ThreadStack> threadStacks;
    std::set<pid_t> tracedLwps;
    {
        StopProcess here(&proc);
        proc.listThreads([&proc, &threadStacks, &tracedLwps] (const td_thrhandle_t *thr) {

            Elf::CoreRegisters regs;
            td_err_e the;
#ifdef __linux__
            the = td_thr_getgregs(thr, (elf_greg_t *) &regs);
#else
            the = td_thr_getgregs(thr, &regs);
#endif
            if (the == TD_OK) {
                threadStacks.push_back(ThreadStack());
                td_thr_get_info(thr, &threadStacks.back().info);
                threadStacks.back().unwind(proc, regs);
                tracedLwps.insert(threadStacks.back().info.ti_lid);
            }

            });

        for (auto &lwp : proc.lwps) {
            if (tracedLwps.find(lwp.first) == tracedLwps.end()) {
                threadStacks.push_back(ThreadStack());
                threadStacks.back().info.ti_lid = lwp.first;
                Elf::CoreRegisters regs;
                proc.getRegs(lwp.first,  &regs);
                threadStacks.back().unwind(proc, regs);
            }
        }
    }

    /*
     * resume at this point - maybe a bit optimistic if a shared library gets
     * unloaded while we print stuff out, but worth the risk, normally.
     */
    if (doJson) {
        os << json(threadStacks, &proc);
    } else {
        os << "process: " << *proc.io << "\n";
        for (auto &s : threadStacks) {
            proc.dumpStackText(os, s, options);
            os << std::endl;
        }
    }
    return os;
}

template<int V> bool doPy(Process &proc, std::ostream &o, const PstackOptions &options) {
#ifdef WITH_PYTHON
    try {
        PythonPrinter<V> printer(proc, o, options);
        if (!printer.interpFound())
            return false;
        printer.printStacks();
    }
    catch (...) {
        return false;
    }
    return true;
#else
	return false;
#endif
}

int
emain(int argc, char **argv)
{
    int i, c;
    pid_t pid;
    std::string execFile;
    Elf::Object::sptr exec;
    Dwarf::ImageCache imageCache;
    double sleepTime = 0.0;
    PstackOptions options;

#if defined(WITH_PYTHON)
    bool python = false;
#endif
    bool coreOnExit = false;

    while ((c = getopt(argc, argv, "F:b:d:CD:hjsVvag:ptz:")) != -1) {
        switch (c) {
        case 'F': g_openPrefix = optarg;
                  break;
        case 'g':
            Elf::globalDebugDirectories.add(optarg);
            break;
        case 'D': {
            auto dumpobj = std::make_shared<Elf::Object>(imageCache, loadFile(optarg));
            auto di = std::make_shared<Dwarf::Info>(dumpobj, imageCache);
            std::cout << json(*di);
            goto done;
        }
        case 'z':
        case 'd': {
            /* Undocumented option to dump image contents */
            std::cout << json(Elf::Object(imageCache, loadFile(optarg)));
            goto done;
        }
        case 'h':
            usage(argv[0]);
            goto done;
        case 'a':
            options.set(PstackOption::doargs);
            break;
        case 'j':
            doJson = true;
            break;
        case 's':
            options.set(PstackOption::nosrc);
            break;
        case 'v':
            verbose++;
            break;
        case 'b':
            sleepTime = strtod(optarg, nullptr);
            break;
        case 'p':
#if defined(WITH_PYTHON)
            python = true;
#else
            std::clog << "no python support compiled in" << std::endl;
#endif
            break;
        case 't':
            options.set(PstackOption::nothreaddb);
            break;

        case 'V':
            std::clog << STR(VERSION) << "\n";
            return 0;
        case 'C':
            coreOnExit = true;
            break;
        default:
            return usage(argv[0]);
        }
    }

    if (optind == argc)
        return usage(argv[0]);

    for (i = optind; i < argc; i++) {
        pid = atoi(argv[i]);
        try {
            auto doStack = [=, &options] (Process &proc) {
                proc.load(options);
                while (!interrupted) {
#if defined(WITH_PYTHON)
                   if (python) {
#ifdef WITH_PYTHON2
                       if (python && doPy<2>(proc, std::cout, options))
                           return;
#endif
#ifdef WITH_PYTHON3
                       doPy<3>(proc, std::cout, options);
                       return;
#endif
                   }
#endif
                   pstack(proc, std::cout, options);
                   if (sleepTime != 0.0) {
                      usleep(sleepTime * 1000000);
                   } else {
                      break;
                   }
               }
            };
            if (pid == 0 || (kill(pid, 0) == -1 && errno == ESRCH)) {
                // It's a file: should be ELF, treat core and exe differently
                // Don't put cores in the cache
                auto obj = std::make_shared<Elf::Object>(imageCache, loadFile(argv[i]));

                if (obj->getHeader().e_type == ET_CORE) {
                    CoreProcess proc(exec, obj, PathReplacementList(), imageCache);
                    doStack(proc);
                } else {
                    exec = obj;
                }
            } else {
                // It's a PID.
                LiveProcess proc(exec, pid, PathReplacementList(), imageCache);
                doStack(proc);
            }
        } catch (const std::exception &e) {
            std::cerr << "failed to process " << argv[i] << ": " << e.what() << "\n";
        }
    }
done:
    if (coreOnExit)
        abort();
    return 0;
}

int
usage(const char *name)
{
    std::clog <<
        "usage: " << name << "\n"
        "\t[-<D|d> <elf object>]        dump details of ELF object (D => show DWARF info\n"
        "or\n"
        "\t[-h]                         show this message\n"
        "or\n"
        "\t[-v]                         include verbose information to stderr\n"
        "\t[-V]                         dump git tag of source\n"
        "\t[-s]                         don't include source-level details\n"
        "\t[-g]                         add global debug directory\n"
        "\t[-a]                         show arguments to functions where possible\n"
        "\t[-n]                         don't try to find external debug images\n"
        "\t[-t]                         don't try to use the thread_db library\n"
        "\t[-b<n>]                      batch mode: repeat every 'n' seconds\n"
#ifdef WITH_PYTHON
        "\t[-p]                         print python backtrace if available\n"
#endif
        "\t[<pid>|<core>|<executable>]* list cores and pids to examine. An executable\n"
        "\t                             will override use of in-core or in-process information\n"
        "\t                             to predict location of the executable\n"
        ;
    return (EX_USAGE);
}

}

int
main(int argc, char **argv)
{
    try {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = [](int) { interrupted = true; };
        // Only interrupt cleanly once. Then just terminate, in case we're stuck in a loop
        sa.sa_flags = SA_RESETHAND;
        sigaction(SIGINT, &sa, nullptr);
        emain(argc, argv);
    }
    catch (std::exception &ex) {
        std::clog << "error: " << ex.what() << std::endl;
        return EX_SOFTWARE;
    }
}
