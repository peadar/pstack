#include <iostream>
#include <algorithm>
#include <memory>
#include "procinfo.h"
#include "elfinfo.h"
#include "dwarf.h"

static int
globmatchR(const char *pattern, const char *name)
{
    for (;; name++) {
        switch (*pattern) {
        case '*':
            // if the rest of the name matches the bit of pattern after '*', 
            for (;;) {
                ++name;
                if (globmatchR(pattern + 1, name))
                    return 1;
                if (*name == 0) // exhuasted name without finding a match
                    return 0;
            }
        default:
            if (*name != *pattern)
                return 0;
        }
        if (*pattern++ == 0)
            return 1;
    }
}

static int
globmatch(std::string pattern, std::string name)
{
    return globmatchR(pattern.c_str(), name.c_str());
}


struct ListedSymbol {
    Elf_Sym sym;
    Elf_Addr addr;
    std::shared_ptr<const ElfObject> obj;
    std::string name;
    ListedSymbol(const Elf_Sym &sym_, Elf_Addr addr_, std::shared_ptr<const ElfObject> obj_, std::string name_)
        : sym(sym_)
        , addr(addr_)
        , obj(obj_)
        , name(name_)
    {
    }
};

struct Symcounter {
    Elf_Addr addr;
    std::string name;
    unsigned count;
    struct ListedSymbol *sym;
};

std::vector<Symcounter> counters;

static const char *virtpattern = "_ZTV*"; /* wildcard for all vtbls */

int
main(int argc, char *argv[])
{
    std::shared_ptr<ElfObject> exec;
    std::shared_ptr<ElfObject> core;
    std::shared_ptr<Process> process;
    int c;

    debug = &std::clog;

    while ((c = getopt(argc, argv, "h")) != -1) {
        switch (c) {
            case 'h': 
                std::clog << "usage: canal [exec] <core>" << std::endl;
                return 0;
        }
    }

    if (argc - optind >= 2) {
        auto file = std::shared_ptr<Reader>(new FileReader(argv[optind]));
        // It's a file:
        exec = std::shared_ptr<ElfObject>(new ElfObject(file));
        optind++;
    }

    if (argc - optind >= 1) {
        char *eoa;
        pid_t pid = strtol(argv[optind], &eoa, 10);
        if (pid != 0 && *eoa == 0 && kill(pid, 0) != -1)
            process = std::shared_ptr<Process>(new LiveProcess(exec, pid));
        else
            process = std::shared_ptr<Process>(new CoreProcess(exec, std::shared_ptr<Reader>(new FileReader(argv[optind]))));
    }
    process->load();
    std::clog << "opened process " << process << std::endl;

    std::vector<ListedSymbol> listed;
    for (auto &loaded : process->objects) {
        std::cout << "found loaded object " << loaded.second->io->describe() << std::endl;
        SymbolSection syms = loaded.second->getSymbols(0);
        for (const auto &sym : syms)
            if (globmatch(virtpattern, sym.second)) {
                listed.push_back(ListedSymbol(sym.first, sym.first.st_value + loaded.first, loaded.second, sym.second));
            }
    }
    std::sort(listed.begin()
        , listed.end()
        , [] (const ListedSymbol &l, const ListedSymbol &r) { return l.addr < r.addr; });

    for (auto &i : listed) {
        std::cout << std::hex << i.addr << " " << i.name << std::endl;
    }

    // Now run through the corefile, searching for virtual objects.
    for (auto &hdr : core->programHeaders) {
    }
}
