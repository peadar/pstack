#include <sysexits.h>
#include <iostream>

#include "dwarf.h"
#include "dump.h"
#include "elfinfo.h"
#include "procinfo.h"

static int usage(void);

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
            auto dumpobj = std::shared_ptr<ElfObject>(
                    new ElfObject(std::shared_ptr<Reader>(new FileReader(optarg, -1))));
            if (c == 'D')
                std::cout << "{ \"elf\": ";
            std::cout << *dumpobj;
            if (c == 'D') {
                DwarfInfo dwarf(dumpobj);
                std::cout << ", \"dwarf\": " << dwarf << "}";
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
            auto file = std::shared_ptr<Reader>(new FileReader(argv[i]));
            // It's a file:
            auto obj = std::shared_ptr<ElfObject>(new ElfObject(file));
            if (obj->elfHeader.e_type == ET_CORE) {
                CoreProcess proc(exec, obj);
                proc.pstack(std::cout);
                if (abortOnExit)
                    abort();
            } else {
                exec = obj;
            }
        } else {
            LiveProcess proc(exec, pid);
            proc.pstack(std::cout);
            if (abortOnExit)
                abort();
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

