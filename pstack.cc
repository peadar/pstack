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
pstack(Process &proc, std::ostream &os, const PstackOptions &options, int maxFrames)
{
    // get its back trace.
    std::list<ThreadStack> threadStacks;
    std::set<pid_t> tracedLwps;
    StopProcess processSuspender(&proc);
    {
        proc.listThreads([&proc, &threadStacks, &tracedLwps, maxFrames] (
                           const td_thrhandle_t *thr) {

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
                threadStacks.back().unwind(proc, regs, maxFrames);
                tracedLwps.insert(threadStacks.back().info.ti_lid);
            }
            });

        for (auto &lwp : proc.lwps) {
            if (tracedLwps.find(lwp.first) == tracedLwps.end()) {
                threadStacks.push_back(ThreadStack());
                threadStacks.back().info.ti_lid = lwp.first;
                Elf::CoreRegisters regs;
                proc.getRegs(lwp.first,  &regs);
                threadStacks.back().unwind(proc, regs, maxFrames);
            }
        }
    }

    // if we don't need to print arguments to functions, we now have the full
    // backtrace and don't need to read anything more from the process.
    // Everything else is just parsing debug data, so we can resume now.
    if (!options.flags[PstackOptions::doargs])
       processSuspender.clear();

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

#ifdef WITH_PYTHON
template<int V> void doPy(Process &proc, std::ostream &o, const PstackOptions &options, bool showModules, const PyInterpInfo &info) {
    StopProcess here(&proc);
    PythonPrinter<V> printer(proc, o, options, info);
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
bool pystack(Process &proc, std::ostream &o, const PstackOptions &options, bool showModules) {
    PyInterpInfo info = getPyInterpInfo(proc);

    if (info.libpython == nullptr) // not a python process or python interpreter not found
        return false;

    if (info.versionHex < V2HEX(3, 0)) { // Python 2.x
#ifdef WITH_PYTHON2
        doPy<2>(proc, o, options, showModules, info);
#else
        throw (Exception() << "no support for discovered python 2 interpreter");
#endif
    } else { // Python 3.x
#ifdef WITH_PYTHON3
        doPy<3>(proc, o, options, showModules, info);
#else
        throw (Exception() << "no support for discovered python 3 interpreter");
#endif
    }

    return true;
}
#endif

int
emain(int argc, char **argv)
{
    int i, c;
    int maxFrames = 1024;
    std::string execFile;
    Elf::Object::sptr exec;
    Dwarf::ImageCache imageCache;
    double sleepTime = 0.0;
    PstackOptions options;
    options.maxdepth = 10000;

#if defined(WITH_PYTHON)
    bool python = false;
    bool pythonModules = false;
#endif
    bool coreOnExit = false;
    bool printAllStacks = false;

    while ((c = getopt(argc, argv, "F:b:d:CD:hjmsVvag:pltz:r:A")) != -1) {
        switch (c) {
        case 'F': {
            const char *sep = strchr(optarg, ':');
            if (sep == 0) {
                usage(argv[0]);
                goto done;
            }
            pathReplacements.push_back(std::make_pair(
                                std::string(optarg, sep - optarg),
                                std::string(sep + 1)));
            break;
        }
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
            options.flags.set(PstackOptions::doargs);
            break;
        case 'j':
            doJson = true;
            break;
        case 's':
            options.flags.set(PstackOptions::nosrc);
            break;
        case 'v':
            verbose++;
            break;
        case 'b':
            sleepTime = strtod(optarg, nullptr);
            break;
        case 'm':
#if defined(WITH_PYTHON)
            pythonModules = true;
#else
            std::clog << "no python support compiled in" << std::endl;
#endif
            break;
        case 'M':
            maxFrames = strtoul(optarg, 0, 0);
            break;
        case 'p':
#if defined(WITH_PYTHON)
            python = true;
#else
            std::clog << "no python support compiled in" << std::endl;
#endif
            break;
        case 'l':
#if defined(WITH_PYTHON)
            options.flags.set(PstackOptions::dolocals);
#else
            std::clog << "no python support compiled in" << std::endl;
#endif
            break;
        case 'A':
            printAllStacks = true;
            break;
        case 't':
            options.flags.set(PstackOptions::nothreaddb);
            break;

        case 'V':
            std::clog << STR(VERSION) << "\n";
            return 0;
        case 'C':
            coreOnExit = true;
            break;
        case 'r':
            options.maxdepth = strtod(optarg, nullptr);
            break;
        default:
            return usage(argv[0]);
        }
    }

    if (optind == argc)
        return usage(argv[0]);

    for (i = optind; i < argc; i++) {
        try {
            auto doStack = [=, &options] (Process &proc) {
                proc.load(options);
                while (!interrupted) {
#if defined(WITH_PYTHON)
                    if (python || printAllStacks) {
                        bool isPythonProcess = pystack(proc, std::cout, options, pythonModules);
                        if (python && !isPythonProcess) 
                            throw Exception() << "Couldn't find a Python interpreter"; // error if -p but not python process
                    }

                    if (!python)
#endif
                    {
                        pstack(proc, std::cout, options, maxFrames);
                    }
                    if (sleepTime != 0.0) {
                        usleep(sleepTime * 1000000);
                    } else {
                        break;
                    }
                }
            };
            auto process = Process::load(exec, argv[i], options, imageCache);
            if (process == nullptr) {
                exec = imageCache.getImageForName(argv[i]);
            } else {
                doStack(*process);
            }
        } catch (const std::exception &e) {
            std::cerr << "trace of " << argv[i] << " failed: " << e.what() << "\n";
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
        "\t[-M<frames>]                 max number of frames (default 1024)\n"
#ifdef WITH_PYTHON
        "\t[-A]                         print all stack traces\n"
        "\t[-p]                         print python backtrace\n"
        "\t[-l]                         show python locals if available\n"
        "\t[-r<n>]                      the max recursion depth for printing\n"
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
