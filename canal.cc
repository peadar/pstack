#include <unistd.h>
#include <fstream>
#include <assert.h>
#include <iostream>
#include <exception>
#include <algorithm>
#include <memory>
#include "procinfo.h"
#include "elfinfo.h"
#include "dwarf.h"

using namespace std;

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
globmatch(string pattern, string name)
{
    return globmatchR(pattern.c_str(), name.c_str());
}


struct ListedSymbol {
    Elf_Sym sym;
    Elf_Off objbase;
    string objname;
    size_t count;
    string name;
    ListedSymbol(const Elf_Sym &sym_, Elf_Off objbase_, string name_, string object)
        : sym(sym_)
        , objbase(objbase_)
        , objname(object)
        , count(0)
        , name(name_)

    {
    }
    Elf_Off memaddr() const { return  sym.st_value + objbase; }
};

bool operator < (const ListedSymbol &sym, Elf_Off addr) {
    return sym.memaddr() + sym.sym.st_size < addr;
}

struct Symcounter {
    Elf_Off addr;
    string name;
    unsigned count;
    struct ListedSymbol *sym;
};

vector<Symcounter> counters;

static const char *virtpattern = "_ZTV*"; /* wildcard for all vtbls */


static bool compareSymbolsByAddress(const ListedSymbol &l, const ListedSymbol &r) { return l.memaddr() < r.memaddr(); };
static bool compareSymbolsByFrequency(const ListedSymbol &l, const ListedSymbol &r) { return l.count > r.count; };
int
mainExcept(int argc, char *argv[])
{
    std::vector<std::string> patterns;
    shared_ptr<ElfObject> exec;
    shared_ptr<ElfObject> core;
    shared_ptr<Process> process;
    int c;
    int verbose = 0;
    bool showaddrs = false;
    int rate = 1;

    std::vector<std::pair<Elf_Off, Elf_Off>> searchaddrs;
    std::vector<std::pair<std::string, std::string>> pathReplacements;
    char *strbuf = 0;
    char *findstr = 0;
    size_t findstrlen;
    int symOffset = -1;
    bool showloaded = false;

    while ((c = getopt(argc, argv, "o:vhr:sp:f:e:S:R:K:y:l")) != -1) {
        switch (c) {
            case 'p':
                virtpattern = optarg;
                break;
            case 's':
                showaddrs = true;
                break;
            case 'v':
                debug = &clog;
                verbose++;
                break;
            case 'h':
                clog << "usage: canal [exec] <core>" << endl;
                return 0;
            case 'o': // offset within a symbol that the pointers must meet.
                symOffset = strtol(optarg, 0, 0);
                break;

            case 'y':
                patterns.push_back(optarg);
                virtpattern = 0;
                break;

            case 'r': {
                char *from = strdup(optarg);
                char *to  = strchr(from, '=');
                if (to == 0)
                    throw "must specify <to>=<from> for '-r'";
                *to++ = 0;
                pathReplacements.push_back(std::make_pair(from, to));
                break;
            }

            case 'S':
                findstr = optarg;
                findstrlen = strlen(findstr);
                strbuf = new char[findstrlen];
                break;

            case 'f': {
                Elf_Off start = strtoll(optarg, 0, 0);
                searchaddrs.push_back(make_pair(start, start + 1));
                break;
            }

            case 'K':
                rate = atoi(optarg);
                break;
            case 'R': {
                std::ifstream in;
                in.open(optarg);
                if (!in.good())
                    abort();
                char buf[1024];
                int count = 0;
                while (in.good()) {
                    in.getline(buf, sizeof buf);
                    if (in.eof())
                        break;
                    if (++count % rate != 0)
                        continue;
                    char *p = buf;
                    while (isspace(*p))
                        p++;
                    Elf_Off start = strtoll(p, &p, 0);
                    while (*p && isspace(*p))
                        p++;
                    Elf_Off end = *p ? strtoll(p, &p, 0) : start + 1;
                    searchaddrs.push_back(make_pair(start, end));
                    std::clog << "push " << hex << start << ", " << end  << " (" << int(*p) << ")" << std::endl;
                }
                break;
            }

            case 'e':
                searchaddrs.back().second = strtoll(optarg, 0, 0);
                break;

            case 'X':
                ps_lgetfpregs(0, 0, 0);
                break;

            case 'l':
                showloaded = true;
                break;
        }
    }

    if (argc - optind >= 2) {
        exec = make_shared<ElfObject>(argv[optind]);
        optind++;
    }


    if (argc - optind < 1) {
        clog << "usage: canal [exec] <core>" << endl;
        return 0;
    }

    core = make_shared<ElfObject>(argv[optind]);
    process = make_shared<CoreProcess>(exec, core, pathReplacements);
    process->load();
    if (searchaddrs.size()) {
        std::clog << "finding references to " << dec << searchaddrs.size() << " addresses\n";
        for (auto iter = searchaddrs.begin(); iter != searchaddrs.end(); ++iter) {
            std::clog << "\t" << iter->first <<" - " << iter->second << "\n";
        }
    }
    clog << "opened process " << process << endl;

    if (showloaded) {
        for (auto loaded = process->objects.begin(); loaded != process->objects.end(); ++loaded)
            std::cout << loaded->object->getName() << "\n";
        exit(0);
    }

    if (virtpattern)
        patterns.push_back(virtpattern);
    vector<ListedSymbol> listed;
    for (auto loaded = process->objects.begin(); loaded != process->objects.end(); ++loaded) {
        size_t count = 0;
        auto syms = loaded->object->getSymbols(".dynsym");
        for (auto sym = syms.begin(); sym != syms.end(); ++sym) {
            for (auto pattern = patterns.begin(); pattern != patterns.end(); ++pattern) {
                if (globmatch(*pattern, (*sym).second)) {
                    listed.push_back(ListedSymbol((*sym).first, loaded->reloc, (*sym).second, loaded->object->io->describe()));
                    count++;
                }
            }
        }
        if (debug)
            *debug << "found " << count << " symbols in " << loaded->object->io->describe() << endl;
    }
    sort(listed.begin() , listed.end() , compareSymbolsByAddress);

    // Now run through the corefile, searching for virtual objects.
    off_t filesize = 0;
    off_t memsize = 0;
    auto segments = core->getSegments();
    for (auto hdr = segments.begin(); hdr != segments.end(); ++hdr) {
        if (hdr->p_type != PT_LOAD)
            continue;
        Elf_Off p;
        filesize += hdr->p_filesz;
        memsize += hdr->p_memsz;
        if (debug) {
            *debug << "scan " << hex << hdr->p_vaddr <<  " to " << hdr->p_vaddr + hdr->p_memsz << " ";
            *debug << "(filesiz = " << hdr->p_filesz  << ", memsiz=" << hdr->p_memsz << ") ";
        }

        if (findstr) {
            for (auto loc = hdr->p_vaddr; loc < hdr->p_vaddr + hdr->p_filesz - findstrlen; loc++) {
                size_t rc = process->io->read(loc, findstrlen, strbuf);
                assert(rc == findstrlen);
                if (memcmp(strbuf, findstr, rc) == 0)
                    std::cout << "0x" << hex << loc << "\n";
            }
        } else {

            for (auto loc = hdr->p_vaddr; loc < hdr->p_vaddr + hdr->p_filesz; loc += sizeof p) {
                if (verbose && (loc - hdr->p_vaddr) % (1024 * 1024) == 0)
                    clog << '.';
                process->io->readObj(loc, &p);
                if (searchaddrs.size()) {
                    for (auto range = searchaddrs.begin(); range != searchaddrs.end(); ++range) {
                        if (p >= range->first && p < range->second && (p % 4 == 0))
                            cout << "0x" << hex << loc << "\n";
                    }
                } else {
                    auto found = lower_bound(listed.begin(), listed.end(), p);
                    if (found != listed.end() &&
                            (symOffset != -1
                                ? found->memaddr() + symOffset == p
                                : found->memaddr() <= p && found->memaddr() + found->sym.st_size > p)) {
                        if (showaddrs)
                            cout << found->name << " 0x" << std::hex << loc <<
                            std::dec <<  " ... size=" << found->sym.st_size <<
                            ", diff=" << p - found->memaddr() << endl;
                        found->count++;
                    }
                }
            }
        }

        if (debug)
            *debug << endl;

    }
    if (debug)
        *debug << "core file contains " << filesize << " out of " << memsize << " bytes of memory\n";

    sort(listed.begin() , listed.end() , compareSymbolsByFrequency);

    for (auto i = listed.begin(); i != listed.end(); ++i)
        if (i->count)
            cout << dec << i->count << " " << i->name << " ( from " << i->objname << ")" << endl;
    return 0;
}

int
main(int argc, char *argv[])
{
    try {
        return mainExcept(argc, argv);
    }
    catch (const exception &ex) {
        cerr << "exception: " << ex.what() << endl;
        return -1;
    }
}
