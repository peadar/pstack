#include "libpstack/dwarf.h"
#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"
#ifdef WITH_PYTHON
#include "libpstack/python.h"
#endif

#include <sys/types.h>

#include <sysexits.h>
#include <unistd.h>

#include <csignal>

#include <iostream>
#include <set>

#define XSTR(a) #a
#define STR(a) XSTR(a)

static bool doJson = false;

extern std::ostream & operator << (std::ostream &os, const JSON<ThreadStack, Process *> &jt);

static int usage();
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

int
emain(int argc, char **argv)
{
    int i, c;
    pid_t pid;
    std::string execFile;
    Elf::Object::sptr exec;
    Dwarf::ImageCache imageCache;
    int sleepTime = 0;
    PstackOptions options;

    bool python = false;

    while ((c = getopt(argc, argv, "F:b:d:D:hjsVvag:pt")) != -1) {
        switch (c) {
        case 'F': g_openPrefix = optarg;
                  break;
        case 'g':
            Elf::globalDebugDirectories.add(optarg);
            break;
        case 'D': {
            auto dumpobj = std::make_shared<Elf::Object>(imageCache, loadFile(optarg));
            Dwarf::Info di(dumpobj, imageCache);
            std::cout << json(di);
            return 0;
        }
        case 'd': {
            /* Undocumented option to dump image contents */
            std::cout << json(Elf::Object(imageCache, loadFile(optarg)));
            return 0;
        }
        case 'h':
            usage();
            return (0);
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
            sleepTime = atoi(optarg);
            break;
        case 'p':
#ifdef WITH_PYTHON
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
        default:
            return usage();
        }
    }

    if (optind == argc)
        return usage();

    do {
       for (i = optind; i < argc; i++) {
           pid = atoi(argv[i]);
           try {
               auto doStack = [python, &options] (Process &proc) {
                   proc.load(options);
#ifdef WITH_PYTHON
                   if (python) {
                       PythonPrinter printer(proc, std::cout, options);
                       printer.printStacks();
                   } else
#endif
                       pstack(proc, std::cout, options);
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
       if (sleepTime != 0)
          sleep(sleepTime);
    } while (sleepTime != 0);
    return 0;
}

int
main(int argc, char **argv)
{
    try {
        emain(argc, argv);
    }
    catch (std::exception &ex) {
        std::clog << "error: " << ex.what() << std::endl;
        return EX_SOFTWARE;
    }
}

static int
usage()
{
    std::clog <<
        "usage: pstack\n"
        "\t[-<D|d> <elf object>]        dump details of ELF object (D => show DWARF info\n"
        "or\n"
        "\t[-h]                         show this message\n"
        "or\n"
        "\t[-v]                         include verbose information to stderr\n"
        "\t[-V]                         dump git tag of source\n"
        "\t[-s]                         don't include source-level details\n"
        "\t[-g]                         add global debug directory\n"
        "\t[-a]                         show arguments to functions where possible (TODO: not finished)\n"
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
