#include <iostream>
#include "dwarf.h"
#include "elfinfo.h"

int
main(int argc, char **argv)
{
    FileReader f(argv[1]);
    const char *str = argv[2];
    size_t len = strlen(str);
    char * buf = new char[len];
    ElfObject o(f);
    
    int phdr = 0;
    for (auto i : o.programHeaders) {
        bool keepGoing = true;
        for (auto addr = i->p_vaddr; keepGoing && addr < i->p_vaddr + i->p_memsz - len; ++i) {
            if (o.io.read(addr, len, buf) != len)
                keepGoing = false;
            if (strncmp(buf, str, len) == 0)
                std::clog << addr << "/" << phdr << "\n";
        }
        phdr++;

    }
}
