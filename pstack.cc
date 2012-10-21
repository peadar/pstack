#include <sysexits.h>
#include <iostream>

#include "dwarf.h"
#include "elfinfo.h"
#include "procinfo.h"

static int usage(void);

int
emain(int argc, char **argv)
{
    int error, i, c;
    pid_t pid;
    std::string execFile;
    ElfObject *exec = 0;
    std::ostream *verbose = 0;

    while ((c = getopt(argc, argv, "a:d:D:e:f:hloOv")) != -1) {
        switch (c) {
        case 'D':
        case 'd': {
            /* Undocumented option to dump image contents */
            FileReader r(optarg, -1);
            ElfObject dumpobj(r);
            if (c == 'D')
                dumpobj.dwarf = new DwarfInfo(&dumpobj);
            std::cout << dumpobj;

            return 0;
        }
        case 'e': {
            execFile = optarg;
            exec = new ElfObject(*new FileReader(optarg));
            break;
        }
        case 'h':
            usage();
            return (0);
        case 'v':
            verbose = &std::clog;
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
            // It's a file:
            FileReader *file = new FileReader(argv[i]);
            ElfObject *obj = new ElfObject(*file);
            if (obj->elfHeader.e_type == ET_CORE) {
                CoreProcess proc(exec, *file, verbose);
                proc.pstack(std::cout);
                delete obj;
            } else {
                delete exec;
                exec = obj;
            }
        } else {
            LiveProcess proc(exec, pid, verbose);
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
        "[-hoOt] "
        "[-a arg count] "
        "[-e executable] "
        "[-f max frame count] "
        "[-l]"
        "pid|core ...\n"
        "\tor\n"
        "\t<-d ELF-file> [-s snaplen]\n";
    return (EX_USAGE);
}

