#include <unistd.h>
#include <signal.h>
#include <fstream>
#include <assert.h>
#include <iostream>
#include <exception>
#include <algorithm>
#include <memory>
#include <sys/types.h>

#include "libpstack/proc.h"
#include "libpstack/elf.h"
#include "libpstack/dwarf.h"
#ifdef WITH_PYTHON
#include "libpstack/python.h"
#endif

using namespace std;

static int
globmatchR(const char *pattern, const char *name)
{
    for (;; name++) {
        switch (*pattern) {
        case '*':
            // if the rest of the name matches the bit of pattern after '*',
            for (;;) {
                if (globmatchR(pattern + 1, name))
                    return 1;
                if (*name == 0) // exhuasted name without finding a match
                    return 0;
                ++name;
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
globmatch(const string &pattern, const string &name)
{
    return globmatchR(pattern.c_str(), name.c_str());
}

struct ListedSymbol {
    Elf::Sym sym;
    Elf::Off objbase;
    string name;
    size_t count;
    string objname;
    ListedSymbol(const Elf::Sym &sym_, Elf::Off objbase_, string name_, string object)
        : sym(sym_)
        , objbase(objbase_)
        , name(name_)
        , count(0)
        , objname(object)
    {}
    Elf::Off memaddr() const { return  sym.st_value + objbase; }
};

class Usage {};

bool operator < (const ListedSymbol &sym, Elf::Off addr) {
    return sym.memaddr() + sym.sym.st_size < addr;
}

static const char *virtpattern = "_ZTV*"; /* wildcard for all vtbls */
static bool compareSymbolsByAddress(const ListedSymbol &l, const ListedSymbol &r)
    { return l.memaddr() < r.memaddr(); }
static bool compareSymbolsByFrequency(const ListedSymbol &l, const ListedSymbol &r)
    { return l.count > r.count; }

ostream &
operator <<(ostream &os, const Usage &)
{
   return os
      << "usage: canal [options] <executable> <core>" << endl
      << "options:" << endl
      << "\t-p <pattern>: use a specific pattern to search (default " << virtpattern << ") (repeatable)" << endl
      << "\t-s: show the address of each located object" << endl
      << "\t-v: verbose (repeat for more verbosity)" << endl
      << "\t-h: this message" << endl
      << "\t-r <prefix=path>: replace 'prefix' in core with 'path' when loading shared libraries" << endl
      ;
}

int
mainExcept(int argc, char *argv[])
{
#ifdef WITH_PYTHON
    bool doPython = false;
#endif
    Dwarf::ImageCache imageCache;
    std::vector<std::string> patterns;
    Elf::Object::sptr exec;
    Elf::Object::sptr core;
    shared_ptr<Process> process;
    int c;
    int verbose = 0;
    bool showaddrs = false;
    bool showsyms = false;
    int rate = 1;

    std::vector<std::pair<Elf::Off, Elf::Off>> searchaddrs;
    std::vector<std::pair<std::string, std::string>> pathReplacements;
    char *strbuf = 0;
    char *findstr = 0;
    size_t findstrlen = 0;
    int symOffset = -1;
    bool showloaded = false;

    while ((c = getopt(argc, argv, "o:vhr:sp:f:Pe:S:R:K:lVt")) != -1) {
        switch (c) {
#ifdef WITH_PYTHON
            case 'P':
               doPython = true;
               patterns.push_back("Py*_Type");
               break;
#endif
            case 'V':
               showsyms = true;
               break;
            case 's':
                showaddrs = true;
                break;
            case 'v':
                verbose++;
                break;
            case 'h':
                clog << Usage();
                return 0;
            case 'o': // offset within a symbol that the pointers must meet.
                symOffset = strtol(optarg, 0, 0);
                break;

            case 'p':
                patterns.push_back(optarg);
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
                Elf::Off start = strtoll(optarg, 0, 0);
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
                    Elf::Off start = strtoll(p, &p, 0);
                    while (*p && isspace(*p))
                        p++;
                    Elf::Off end = *p ? strtoll(p, &p, 0) : start + 1;
                    searchaddrs.push_back(make_pair(start, end));
                    IOFlagSave _(std::clog);
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
        exec = imageCache.getImageForName(argv[optind]);
        optind++;
    }

    if (argc - optind < 1) {
        clog << Usage();
        return 0;
    }

    pid_t pid = 0;
    std::istringstream(argv[optind]) >> pid;
    if (pid != 0 && kill(pid, 0) == 0) {
       std::clog << "attaching to live process" << std::endl;
       process = make_shared<LiveProcess>(exec, pid, pathReplacements, imageCache);
    } else {
       core = make_shared<Elf::Object>(imageCache, loadFile(argv[optind]));
       process = make_shared<CoreProcess>(exec, core, pathReplacements, imageCache);
    }
    process->load(PstackOptions());

    if (searchaddrs.size()) {
        std::clog << "finding references to " << dec << searchaddrs.size() << " addresses\n";
        for (auto &addr : searchaddrs)
            std::clog << "\t" << addr.first <<" - " << addr.second << "\n";
    }
    clog << "opened process " << process << endl;

    if (showloaded) {
        for (auto loaded = process->objects.begin(); loaded != process->objects.end(); ++loaded)
            std::cout << *loaded->object->io << "\n";
        exit(0);
    }

    if (patterns.empty())
        patterns.push_back(virtpattern);

    vector<ListedSymbol> listed;
    for (auto loaded = process->objects.begin(); loaded != process->objects.end(); ++loaded) {
        size_t count = 0;

        struct Elf::SymbolSection symtabs[2] = {
           loaded->object->getSymbols(".dynsym"),
           loaded->object->getSymbols(".symtab")
        };

        for (auto &syms : symtabs) {
           for (auto sym = syms.begin(); sym != syms.end(); ++sym) {
               for (auto &pattern : patterns) {
                   auto &name = (*sym).second;
                   if (globmatch(pattern, name)) {
                       listed.push_back(ListedSymbol((*sym).first,
                                loaded->loadAddr, name, stringify(*loaded->object->io)));
                       if (verbose > 1 || showsyms)
                          std::cout << (*sym).second << "\n";
                       count++;
                   }
               }
           }
        }
        if (verbose)
            *debug << "found " << count << " symbols in " << *loaded->object->io << endl;
    }
    if (showsyms)
       exit(0);
    sort(listed.begin() , listed.end() , compareSymbolsByAddress);

    // Now run through the corefile, searching for virtual objects.
    off_t filesize = 0;
    off_t memsize = 0;
#ifdef WITH_PYTHON
    PythonPrinter py(*process, std::cout, PstackOptions());
#endif
    for (auto &hdr : core->getSegments(PT_LOAD)) {
        Elf::Off p;
        filesize += hdr.p_filesz;
        memsize += hdr.p_memsz;
        int seg_count = 0;
        if (verbose) {
            IOFlagSave _(*debug);
            *debug << "scan " << hex << hdr.p_vaddr <<  " to " << hdr.p_vaddr + hdr.p_memsz
                << " (filesiz = " << hdr.p_filesz  << ", memsiz=" << hdr.p_memsz << ") ";
        }

        if (findstr) {
            for (auto loc = hdr.p_vaddr; loc < hdr.p_vaddr + hdr.p_filesz - findstrlen; loc++) {
                size_t rc = process->io->read(loc, findstrlen, strbuf);
                assert(rc == findstrlen);
                if (memcmp(strbuf, findstr, rc) == 0) {
                    IOFlagSave _(cout);
                    std::cout << "0x" << hex << loc << "\n";
                }
            }
        } else {
            for (auto loc = hdr.p_vaddr; loc < hdr.p_vaddr + hdr.p_filesz; loc += sizeof p) {
                // log a '.' every megabyte.
                if (verbose && (loc - hdr.p_vaddr) % (1024 * 1024) == 0)
                    clog << '.';
                process->io->readObj(loc, &p);
                if (searchaddrs.size()) {
                    for (auto range = searchaddrs.begin(); range != searchaddrs.end(); ++range) {
                        if (p >= range->first && p < range->second && (p % 4 == 0)) {
                            IOFlagSave _(cout);
                            cout << "0x" << hex << loc << "\n";
                        }
                    }
                } else {
                    auto found = lower_bound(listed.begin(), listed.end(), p);
                    if (found != listed.end() &&
                            (symOffset != -1
                                ? found->memaddr() + symOffset == p
                                : found->memaddr() <= p && found->memaddr() + found->sym.st_size > p)) {
                        if (showaddrs)
                            cout
                                << found->name << " 0x" << std::hex << loc
                                << std::dec <<  " ... size=" << found->sym.st_size
                                << ", diff=" << p - found->memaddr() << endl;
#if WITH_PYTHON
                        if (doPython) {
                            std::cout << "pyo " << Elf::Addr(loc) << " ";
                            py.print(Elf::Addr(loc) - sizeof (PyObject) + sizeof (struct _typeobject *));
                            std::cout << "\n";
                        }
#endif
                        found->count++;
                        seg_count++;
                    }
                }
            }
        }

        if (verbose)
            *debug << seg_count << endl;

    }
    if (verbose)
        *debug << "core file contains " << filesize << " out of " << memsize << " bytes of memory\n";

    sort(listed.begin() , listed.end() , compareSymbolsByFrequency);

    for (auto &i : listed)
        if (i.count)
            cout << dec << i.count << " " << i.name << " ( from " << i.objname << ")" << endl;
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
