/*
 * Canal searches through core files looking for references to symbols.  The
 * symbols can be provided by a glob style pattern, and defaults to a pattern
 * that matches symbols associated with vtables.  So, by default, canal finds
 * likely instances of classes with virtual methods in the process's address
 * space, and can be useful to help identify memory leaks.
 */

#include <unistd.h>
#include <signal.h>
#include <fstream>
#include <assert.h>
#include <iostream>
#include <exception>
#include <algorithm>
#include <memory>
#include <sys/types.h>
#include <map>

#include "libpstack/proc.h"
#include "libpstack/elf.h"
#include "libpstack/dwarf.h"
#ifdef WITH_PYTHON
#include "libpstack/python.h"
#endif

#ifdef WITH_PYTHON
#undef WITH_PYTHON
#endif
using namespace std;

// does "name" match the glob pattern "pattern"?
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

class SymbolStore {
    std::map<Elf::Off, ListedSymbol> store_;
public:

    void add(ListedSymbol symbol) {
        store_.emplace(symbol.memaddr() + symbol.sym.st_size, symbol);
    }

    template <typename Match>
    std::tuple<bool, ListedSymbol*> find(Elf::Off address, const Match match) {
        auto pos = store_.lower_bound(address);
        auto sym = &pos->second;
        if (pos != store_.end() && match(address, sym)) {
            return std::make_tuple(true, sym);
        }
        return std::make_tuple(false, nullptr);
    }

    std::vector<ListedSymbol> flatten() const {
        std::vector<ListedSymbol> retv;
        retv.reserve(store_.size());
        for(const auto & item : store_) {
            retv.emplace_back( item.second );
        }
        return retv;
    }
};

class OffsetFreeSymbolMatcher {
public:
    bool operator()(Elf::Off address, const ListedSymbol * sym) const {
      return sym->memaddr() <= address && sym->memaddr() + sym->sym.st_size > address;
    }
};

class OffsetBoundSymbolMatcher {
   const Elf::Off offset_;
public:
    OffsetBoundSymbolMatcher(Elf::Addr offset): offset_(offset) {}
    bool operator()(Elf::Off address, const ListedSymbol * sym) const {
       return sym->memaddr() + offset_ == address;
    }
};

class Usage {};

bool operator < (const ListedSymbol &sym, Elf::Off addr) {
    return sym.memaddr() + sym.sym.st_size < addr;
}

static const char *virtpattern = "_ZTV*"; /* wildcard for all vtbls */
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
    int c;
    int verbose = 0;
    bool showaddrs = false;
    bool showsyms = false;
    int rate = 1;

    std::vector<std::pair<Elf::Off, Elf::Off>> searchaddrs;
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
                    std::clog << "push " << hex << start << ", " << end
                       << " (" << int(*p) << ")" << std::endl;
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

    auto process = Process::load(exec, argv[optind], PstackOptions(), imageCache);
    if (searchaddrs.size()) {
        std::clog << "finding references to " << dec << searchaddrs.size() << " addresses\n";
        for (auto &addr : searchaddrs)
            std::clog << "\t" << addr.first <<" - " << addr.second << "\n";
    }
    clog << "opened process " << process << endl;

    if (showloaded) {
        for (auto &loaded : process->objects)
            std::cout << *loaded.second->io << "\n";
        exit(0);
    }

    if (patterns.empty())
        patterns.push_back(virtpattern);

    SymbolStore store;
    for (auto &loaded : process->objects) {
        size_t count = 0;

        auto findSymbols = [&count, verbose, showsyms, &store, &patterns, &loaded]( auto table ) {
           for (const auto &sym : *table) {
               for (auto &pattern : patterns) {
                   auto name = table->name(sym);
                   if (globmatch(pattern, name)) {
                       store.add(ListedSymbol(sym, loaded.first,
                                name, stringify(*loaded.second->io)));
                       if (verbose > 1 || showsyms)
                          std::cout << name << "\n";
                       count++;
                   }
               }
           }
        };

        findSymbols( loaded.second->dynamicSymbols() );
        findSymbols( loaded.second->debugSymbols() );

        if (verbose)
            *debug << "found " << count << " symbols in " << *loaded.second->io << endl;
    }
    if (showsyms)
       exit(0);

    // Now run through the corefile, searching for virtual objects.
    Elf::Off filesize = 0;
    Elf::Off memsize = 0;
#ifdef WITH_PYTHON
    PythonPrinter<2> py(*process, std::cout, PstackOptions());
#endif
    std::vector<Elf::Off> data;
    auto as = process->addressSpace();
    for (auto &segment : as ) {
        filesize += segment.fileSize;
        memsize += segment.memSize;
        int seg_count = 0;
        if (verbose) {
            IOFlagSave _(*debug);
            *debug << "scan " << hex << segment.start <<  " to " << segment.start + segment.memSize
                << " (filesiz = " << segment.fileSize  << ", memsiz=" << segment.memSize << ") ";
        }

        if (findstr) {
            for (auto loc = segment.start; loc < segment.start + segment.fileSize - findstrlen; loc++) {
                size_t rc = process->io->read(loc, findstrlen, strbuf);
                assert(rc == findstrlen);
                if (memcmp(strbuf, findstr, rc) == 0) {
                    IOFlagSave _(cout);
                    std::cout << "0x" << hex << loc << "\n";
                }
            }
        } else {
            auto search = [&](auto m) {
                const size_t step = sizeof(Elf::Off);
                const size_t chunk_size = 1'048'576;
                Elf::Addr loc=segment.start;
                const Elf::Addr end_loc = loc + segment.fileSize;
                while (loc < end_loc) {
                    size_t read_size = std::min(chunk_size, end_loc - loc);
                    data.resize(read_size/step);
                    try {
                        read_size = process->io->read(loc, read_size, reinterpret_cast<char*>(data.data()));
                    }
                    catch (const std::exception &ex) {
                        std::cerr << "error reading chunk from core: " << ex.what() << std::endl;
                        loc = end_loc;
                        continue;
                    }
                    data.resize(read_size / step);
                    if (verbose) {
                        // log a '.' every megabyte.
                        clog << '.';
                    }
                    for (auto it=data.begin(); it != data.end(); ++it, loc+=step) {
                        const auto & p=*it;
                        if (searchaddrs.size()) {
                            for (auto range = searchaddrs.begin(); range != searchaddrs.end(); ++range) {
                                if (p >= range->first && p < range->second && (p % 4 == 0)) {
                                    IOFlagSave _(cout);
                                    cout << "0x" << hex << loc << dec << "\n";
                                }
                            }
                        } else {
                            bool found;
                            ListedSymbol * sym;
                            std::tie(found, sym) = store.find(p, m);
                            if (found) {
                                if (showaddrs)
                                    cout
                                        << sym->name << " 0x" << std::hex << loc
                                        << std::dec <<  " ... size=" << sym->sym.st_size
                                        << ", diff=" << p - sym->memaddr() << endl;
#if 0 && WITH_PYTHON
                                if (doPython) {
                                    std::cout << "pyo " << Elf::Addr(loc) << " ";
                                    py.print(Elf::Addr(loc) - sizeof (PyObject) +
                                        sizeof (struct _typeobject *));
                                    std::cout << "\n";
                                }
#endif
                                sym->count++;
                                seg_count++;
                            }
                        }
                    }
                }
            };
            if (symOffset > 0)
                search(OffsetBoundSymbolMatcher(symOffset));
            else
                search(OffsetFreeSymbolMatcher());
        }

        if (verbose)
            *debug << seg_count << endl;

    }
    if (verbose)
        *debug << "core file contains " << filesize << " out of "
           << memsize << " bytes of memory\n";
    auto histogram = store.flatten();
    sort(histogram.begin(), histogram.end(), compareSymbolsByFrequency);

    for (auto &i : histogram)
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
