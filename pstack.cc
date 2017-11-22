#include <sysexits.h>
#include <unistd.h>
#include <iostream>
#include <sys/types.h>
#include <signal.h>

#include <libpstack/dwarf.h>
#include <libpstack/dump.h>
#include <libpstack/elf.h>
#include <libpstack/proc.h>
#include <libpstack/ps_callback.h>

static bool python;
extern std::ostream & pythonStack(Process &proc, std::ostream &os, const PstackOptions &);

struct ThreadLister {

    std::list<ThreadStack> threadStacks;
    Process *process;

    ThreadLister(Process *process_ ) : process(process_) {}

    void operator() (const td_thrhandle_t *thr) {
        CoreRegisters regs;
        td_err_e the;
#ifdef __linux__
        the = td_thr_getgregs(thr, (elf_greg_t *) &regs);
#else
        the = td_thr_getgregs(thr, &regs);
#endif
        if (the == TD_OK) {
            threadStacks.push_back(ThreadStack());
            td_thr_get_info(thr, &threadStacks.back().info);
            threadStacks.back().unwind(*process, regs);
        }
    }
};

static int usage(void);
std::ostream &
pstack(Process &proc, std::ostream &os, const PstackOptions &options)
{

    // get its back trace.
    ThreadLister threadLister(&proc);
    {
        StopProcess here(&proc);
        proc.listThreads(threadLister);
        if (threadLister.threadStacks.empty()) {
            // get the register for the process itself, and use those.
            CoreRegisters regs;
            proc.getRegs(ps_getpid(&proc),  &regs);
            threadLister.threadStacks.push_back(ThreadStack());
            threadLister.threadStacks.back().unwind(proc, regs);
        }
    }

    /*
     * resume at this point - maybe a bit optimistic if a shared library gets
     * unloaded while we print stuff out, but worth the risk, normally.
     */
    os << "process: " << *proc.io << "\n";
    for (auto s = threadLister.threadStacks.begin(); s != threadLister.threadStacks.end(); ++s) {
        proc.dumpStackText(os, *s, options);
        os << "\n";
    }
    return os;
}

int
emain(int argc, char **argv)
{
    int i, c;
    pid_t pid;
    std::string execFile;
    std::shared_ptr<ElfObject> exec;
    DwarfImageCache imageCache;
    int sleepTime = 0;

    PstackOptions options;
    noDebugLibs = false;

    while ((c = getopt(argc, argv, "b:d:D:hsvnag:p")) != -1) {
        switch (c) {
        case 'g':
            globalDebugDirectories.add(optarg);
            break;
        case 'D': {
            auto dumpobj = std::make_shared<ElfObject>(imageCache, loadFile(optarg));
            DwarfInfo di(ElfObject::getDebug(dumpobj), imageCache);
            std::cout << di;
            return 0;
        }
        case 'd': {
            /* Undocumented option to dump image contents */
            std::cout << ElfObject(imageCache, loadFile(optarg));
            return 0;
        }
        case 'h':
            usage();
            return (0);
        case 'a':
            options += PstackOptions::doargs;
            break;
        case 's':
            options += PstackOptions::nosrc;
            break;
        case 'v':
            verbose++;
            break;
        case 'n':
            noDebugLibs = true;
            break;
        case 'b':
            sleepTime = atoi(optarg);
            break;
        case 'p':
            python = true;
            break;
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
               if (pid == 0 || (kill(pid, 0) == -1 && errno == ESRCH)) {
                   // It's a file: should be ELF, treat core and exe differently

                   // Don't put cores in the cache
                   auto obj = std::make_shared<ElfObject>(imageCache, loadFile(argv[i]));

                   if (obj->getElfHeader().e_type == ET_CORE) {
                           CoreProcess proc(exec, obj, PathReplacementList(), imageCache);
                           proc.load();
                           if (python)
                               pythonStack(proc, std::cout, options);
                           else
                               pstack(proc, std::cout, options);

                   } else {
                       exec = obj;
                   }
               } else {
                   LiveProcess proc(exec, pid, PathReplacementList(), imageCache);
                   proc.load();
                   if (python)
                       pythonStack(proc, std::cout, options);
                   else
                       pstack(proc, std::cout, options);
               }

           } catch (const std::exception &e) {
               std::cout << "failed to process " << argv[i] << ": " << e.what() << "\n";
           }
       }
       if (sleepTime)
          sleep(sleepTime);
    } while (sleepTime != 0);
    return 0;
}

int
main(int argc, char **argv)
{
    try {
        return emain(argc, argv);
    }
    catch (std::exception &ex) {
        std::clog << "error: " << ex.what() << std::endl;
        return EX_SOFTWARE;
    }
}

static int
usage(void)
{
    std::clog <<
        "usage: pstack\n"
        "\t[-<D|d> <elf object>]        dump details of ELF object (D => show DWARF info\n"
        "or\n"
        "\t[-h]                         show this message\n"
        "or\n"
        "\t[-v]                         include verbose information to stderr\n"
        "\t[-s]                         don't include source-level details\n"
        "\t[-g]                         add global debug directory\n"
        "\t[-a]                         show arguments to functions where possible (TODO: not finished)\n"
        "\t[-n]                         don't try and find external debug images\n"
        "\t[-b<n>]                      batch mode: repeat every 'n' seconds\n"
        "\t[<pid>|<core>|<executable>]* list cores and pids to examine. An executable\n"
        "\t                             will override use of in-core or in-process information\n"
        "\t                             to predict location of the executable\n"
        ;
    return (EX_USAGE);
}
