#include <iostream>
#include <algorithm>
#include <memory>
#include "procinfo.h"
#include "elfinfo.h"
#include "dwarf.h"

extern "C" {
#include "proc_service.h"
}

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
    std::string objname;
    size_t count;
    std::string name;
    ListedSymbol(const Elf_Sym &sym_, Elf_Off objbase_, std::string name_, std::string object)
        : sym(sym_)
        , objbase(objbase_)
        , name(name_)
        , count(0)
        , objname(object)

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
    int verbose = 0;

    while ((c = getopt(argc, argv, "vh")) != -1) {
        switch (c) {
            case 'v': 
                debug = &std::clog;
                verbose++;
                break;
            case 'h': 
                std::clog << "usage: canal [exec] <core>" << std::endl;
                return 0;
            case 'X':
                ps_lgetfpregs(0, 0, 0);
        }
    }

    if (argc - optind >= 2) {
        auto file = std::make_shared<FileReader>(argv[optind]);
        // It's a file:
        exec = std::make_shared<ElfObject>(file);
        optind++;
    }

    if (argc - optind >= 1) {
        char *eoa;
        pid_t pid = strtol(argv[optind], &eoa, 10);
        core = std::make_shared<ElfObject>(std::make_shared<FileReader>(argv[optind]));
        process = std::make_shared<CoreProcess>(exec, core);
    }
    std::clog << "opened process " << process << std::endl;

    std::vector<ListedSymbol> listed;
    for (auto &loaded : process->objects) {
        size_t count = 0;
        for (const auto &sym : loaded.object->getSymbols(".dynsym")) {
            if (globmatch(virtpattern, sym.second)) {
                listed.push_back(ListedSymbol(sym.first, loaded.reloc, sym.second, loaded.object->io->describe()));
                count++;
            }
        }
        if (debug)
            *debug << "found " << count << " symbols in " << loaded.object->io->describe() << std::endl;
    }
    std::sort(listed.begin()
        , listed.end()
        , [] (const ListedSymbol &l, const ListedSymbol &r) { return l.memaddr() < r.memaddr(); });

    // Now run through the corefile, searching for virtual objects.
    for (auto hdr : core->getSegments()) {
        if (hdr.p_type != PT_LOAD)
            continue;
        Elf_Off p;
        auto loc = hdr.p_vaddr;
        auto end = loc + hdr.p_filesz;
        if (debug)
            *debug << "scan " << std::hex << loc <<  " to " << end;

        for (Elf_Off readCount = 0; loc  < hdr.p_vaddr + hdr.p_filesz; loc += sizeof p) {
            if (verbose && (loc - hdr.p_vaddr) % (1024 * 1024) == 0)
                std::clog << '.';
            process->io->readObj(loc, &p);
            auto found = std::lower_bound(listed.begin(), listed.end(), p);
            if (found != listed.end() && found->memaddr() <= p && found->memaddr() + found->sym.st_size > p) {
                // std::cout << found->name << " " << loc << std::endl;
                found->count++;
            }
        }
        if (debug)
            *debug << std::endl;
    }

    std::sort(listed.begin()
        , listed.end()
        , [] (const ListedSymbol &l, const ListedSymbol &r) { return l.count > r.count; });

    for (auto &i : listed)
        if (i.count)
            std::cout << std::dec << i.count << " " << i.name << " ( from " << i.objname << ")" << std::endl;
}
