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
    Elf_Off objbase;
    size_t count;
    std::string name;
    ListedSymbol(const Elf_Sym &sym_, Elf_Off objbase_, std::string name_)
        : sym(sym_)
        , objbase(objbase_)
        , name(name_)
        , count(0)

    {
    }
    Elf_Off memaddr() const { return  sym.st_value + objbase; }
};

const bool operator < (const ListedSymbol &sym, Elf_Off addr) {
    return sym.memaddr() + sym.sym.st_size < addr;
}

struct Symcounter {
    Elf_Off addr;
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
        else {
            core = std::shared_ptr<ElfObject>(new ElfObject(std::shared_ptr<Reader>(new FileReader(argv[optind]))));
            process = std::shared_ptr<Process>(new CoreProcess(exec, core));
        }
    }
    process->load();
    std::clog << "opened process " << process << std::endl;

    std::vector<ListedSymbol> listed;
    for (auto &loaded : process->objects) {
        std::cout << "found loaded object " << loaded.second->io->describe() << std::endl;
        SymbolSection syms = loaded.second->getSymbols(0);
        for (const auto &sym : syms)
            if (globmatch(virtpattern, sym.second))
                listed.push_back(ListedSymbol(sym.first, loaded.first, sym.second));
    }
    std::sort(listed.begin()
        , listed.end()
        , [] (const ListedSymbol &l, const ListedSymbol &r) { return l.memaddr() < r.memaddr(); });

    std::clog << "core at " << core << std::endl;

    // Now run through the corefile, searching for virtual objects.
    for (auto hdr : core->programHeaders) {
        if (hdr->p_type != PT_LOAD)
            continue;
        Elf_Off p;
        auto loc = hdr->p_vaddr;
        for (Elf_Off readCount = 0; loc  < hdr->p_vaddr + hdr->p_filesz; loc += sizeof p) {
            process->io->readObj(loc, &p);
            auto found = std::lower_bound(listed.begin(), listed.end(), p);
            if (found != listed.end() && found->memaddr() <= p && found->memaddr() + found->sym.st_size > p) {
                std::cout << found->name << " " << loc << std::endl;
                found->count++;
            }
        }
        for (auto &i : listed)
            if (i.count)
                std::cout << std::hex << i.count << " " << i.name << std::endl;
    }
}
