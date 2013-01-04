#include <sysexits.h>
#include <iostream>

#include "dwarf.h"
#include "dump.h"
#include "elfinfo.h"
#include "procinfo.h"

extern "C" {
#include "proc_service.h"
}


static int usage(void);


std::ostream &
Process::pstack(std::ostream &os)
{
    ps_pstop(this);

    std::list<ThreadStack> threadStacks;

    // get its back trace.

    listThreads(
        [&threadStacks, this](const td_thrhandle_t *thr) {
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
                threadStacks.back().unwind(*this, regs);
            }
    });

    if (threadStacks.empty()) {
        // get the register for the process itself, and use those.
        CoreRegisters regs;
        getRegs(ps_getpid(this),  &regs);
        threadStacks.push_back(ThreadStack());
        threadStacks.back().unwind(*this, regs);
    }


    ps_pcontinue(this);
    /*
     * resume at this point - maybe a bit optimistic if a shared library gets
     * unloaded while we print stuff out, but worth the risk, normally.
     */
    const char *sep = "";
    for (auto &s : threadStacks) {
        dumpStackText(os, s);
        os << "\n";
        sep = ", ";
    }
    return os;
}


int
emain(int argc, char **argv)
{
    int error, i, c;
    pid_t pid;
    std::string execFile;
    std::shared_ptr<ElfObject> exec;
    bool abortOnExit = false;

    while ((c = getopt(argc, argv, "ad:D:hv")) != -1) {
        switch (c) {
        case 'a':
            abortOnExit = true;
            break;
        case 'D':
        case 'd': {
            /* Undocumented option to dump image contents */
            auto dumpobj = std::make_shared<ElfObject>(std::make_shared<FileReader>(optarg, -1));
            if (c == 'D')
                std::cout << "{ \"elf\": ";
            std::cout << *dumpobj;
            if (c == 'D') {
                auto dwarf = make_unique<DwarfInfo>(dumpobj);
                std::cout << ", \"dwarf\": " << *dwarf << "}";
            }
            return 0;
        }
        case 'h':
            usage();
            return (0);
        case 'v':
            debug = &std::clog;
            break;
        default:
            return usage();
        }
    }

    if (optind == argc)
        return usage();

    for (error = 0, i = optind; i < argc; i++) {
        pid = atoi(argv[i]);
        if (pid == 0 || (kill(pid, 0) == -1 && errno == ESRCH)) {
            // It's a file: should be ELF, treat core and exe differently
            auto obj = std::make_shared<ElfObject>(std::make_shared<FileReader>(argv[i]));
            if (obj->getElfHeader().e_type == ET_CORE) {
                CoreProcess proc(exec, obj);
                proc.load();
                proc.pstack(std::cout);
            } else {
                exec = obj;
            }
        } else {
            LiveProcess proc(exec, pid);
            proc.load();
            proc.pstack(std::cout);
        }
    }
    return (error);
}

int
main(int argc, char **argv)
{
    try {
        emain(argc, argv);
    }
    catch (std::exception &ex) {
        std::clog << "error: " << ex.what() << std::endl;
    }
}

static int
usage(void)
{
    std::clog <<
        "usage: pstack\n\t"
        "[-D <elf object>]           dump details of ELF object (including DWARF info)\n\t"
        "[-d <elf object>]           dump details of ELF object\n"
        "or\n\t"
        "[-h]                        show this message\n"
        "or\n\t"
        "[-v]                        include verbose information to stderr\n\t"
        "[<pid>|<core>|<executable>] list cores and pids to examine. An executable\n\t"
        "                            will override use of in-core or in-process information\n\t"
        "                            to predict location of the executable\n"
        ;
    return (EX_USAGE);
}

