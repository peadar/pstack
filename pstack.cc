#include <sys/param.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <sys/ptrace.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <iostream>
#include <set>
#include "dwarf.h"
#include "dump.h"

extern "C" {
#include <thread_db.h>
#include "proc_service.h"
}
#include "elfinfo.h"
#include "procinfo.h"
#include "dwarf.h"

/*
 * Command-line flags
 */

/* Prototypes */
static int usage(void);

int
main(int argc, char **argv)
{
    int error, i, c;
    pid_t pid;
    std::string execFile, coreFile;


    while ((c = getopt(argc, argv, "a:d:D:e:f:hloOv")) != -1) {
        switch (c) {
        case 'D':
        case 'd': {
            /* Undocumented option to dump image contents */
            FileReader r(optarg);
            ElfObject dumpobj(r);
            if (c == 'D')
                dumpobj.dwarf = new DwarfInfo(&dumpobj);
            std::cout << dumpobj;

            return 0;
        }

        case 'e':
            execFile = optarg;
            break;

        case 'h':
            usage();
            return (0);

        default:
            return (usage());
        }
    }
    if (optind == argc)
        return (usage());

    for (error = 0, i = optind; i < argc; i++) {
        pid = atoi(argv[i]);
        FileReader execData(execFile);
        if (pid == 0 || (kill(pid, 0) == -1 && errno == ESRCH)) {
            FileReader coreFile(argv[i]);
            CoreProcess proc(execData, coreFile);
            proc.pstack(std::cout);
        } else {
            LiveProcess proc(execData, pid);
            proc.pstack(std::cout);
        }
    }
    return (error);
}

static int
usage(void)
{
    fprintf(stderr, "usage: pstack\n\t"
        "[-hoOt] "
        "[-a arg count] "
        "[-e executable] "
        "[-f max frame count] "
        "[-l]"
        "pid|core ...\n"
        "\tor\n"
        "\t<-d ELF-file> [-s snaplen]\n");
    return (EX_USAGE);
}

