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
#include "libpstack/stringify.h"
#include "libpstack/global.h"
#include "libpstack/fs.h"
#include "libpstack/ioflag.h"
#include "libpstack/flags.h"
#ifdef WITH_PYTHON
#include "libpstack/python.h"
#endif

#ifdef WITH_PYTHON
#undef WITH_PYTHON
#endif
using namespace std;
using namespace pstack;

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

struct Usage {
   const Flags &flags;
   Usage(Flags &flags) : flags(flags) {}
};

bool operator < (const ListedSymbol &sym, Elf::Off addr) {
    return sym.memaddr() + sym.sym.st_size < addr;
}

static const char *virtpattern = "_ZTV*"; /* wildcard for all vtbls */

ostream &
operator <<(ostream &os, const Usage &u)
{
   return os <<
R"---(
Nominally, Canal finds references to symbols matching a specific set
of patterns within a core file or process, and produces a histogram
showing the frequency of occurrances of references to each mached symbol.
By default, it will find references to vtables (by matching the pattern
'_ZTV*', which starts the mangled name of a vtable), but you can use
your own pattern to find references to similar type-describing objects.

In the default operating mode, it gives a pretty accurate estimate of
the number each type of polymorphic C++ object allocated in the process.
You may also use canal to find references to specific addresses, or
references that lie within a specific range of addresses.

This whole thing should be a python extension module to allow much finer
control over its operation.

usage:
canal [options] [executable] <core|pid>

options:
)---" << u.flags;

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
    bool showaddrs = false;
    bool showsyms = false;

    std::vector<std::pair<Elf::Off, Elf::Off>> searchaddrs;
    std::string findstr;
    int symOffset = -1;

    Flags flags;

    flags
#ifdef WITH_PYTHON
    .add("python", 'P', "try to find python objects", setf(doPython))
#endif
    .add("show-syms", 'V', "show symbols matching search pattern", Flags::setf(showsyms))
    .add("show-addrs", 's', "show adddress of references found in core", Flags::setf(showaddrs))
    .add("verbose", 'v', "increase verbosity (may be repeated)", [&]() { ++verbose; })
    .add("help", 'h', "show this message", [&]() { std::cout << Usage(flags); exit(0); })
    .add("offset",
          'o',
          "offset from symbol location",
          "limit search to matches that are exactly <offset> from the symbol",
          Flags::set(symOffset))
    .add("pattern", 'p', "glob",
          "add <glob> to the list of patterns to be matched for symbols",
          [&](const char *data) { patterns.push_back(data); })
    .add("replace-path", 'r', "from:to",
          "replace references to path <from> with <tp> when finding libraries",
          [&](const char *data) {
             std::string both = data;
             size_t colon = both.find(':');
             if (colon == std::string::npos)
                throw "must specify <to>=<from> for '-r'";
             pathReplacements.push_back(std::make_pair(both.substr(0, colon), both.substr(colon + 1)));
          })
    .add("start-location", 'f', "addresss",
          "instead of searching for symbols, find references to a specified address. Decimal, or prefix with 0x for hex",
          [&](const char *p) {
          Elf::Off start = strtoul(p, 0, 0);
          searchaddrs.push_back(make_pair(start, start + 1));
          })
    .add("end-location", 'e', "end-address",
          "change previous 'f' option to include all addresses in range ['f' addr, 'e' addr)",
          [&](const char *p) { searchaddrs.back().second = strtoul(p, 0, 0); })
    .add("string", 'S', "text", "search the core for the text string <text>, and print it's address", Flags::set(findstr))
    .parse(argc, argv);

    if (argc - optind >= 2) {
        exec = imageCache.getImageForName(argv[optind]);
        optind++;
    }

    if (argc - optind < 1) {
        clog << Usage(flags);
        return 0;
    }

    auto process = Procman::Process::load(exec, argv[optind], PstackOptions(), imageCache);
    if (searchaddrs.size()) {
        std::clog << "finding references to " << dec << searchaddrs.size() << " addresses\n";
        for (auto &addr : searchaddrs)
            std::clog << "\t" << addr.first <<" - " << addr.second << "\n";
    }
    clog << "opened process " << process << endl;

    SymbolStore store;

    if (patterns.empty())
        patterns.push_back(virtpattern);

    for (auto &loaded : process->objects) {
        size_t count = 0;
        auto findSymbols = [&count, showsyms, &store, &patterns, &loaded]( auto table ) {
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
#ifdef WITH_PYTHON
    PythonPrinter<2> py(*process, std::cout, PstackOptions());
#endif
    std::vector<Elf::Off> data;
    auto as = process->addressSpace();
    for (auto &segment : as ) {
        if (verbose) {
            IOFlagSave _(*debug);
            *debug << "scan " << hex << segment.start <<  " to " << segment.start + segment.end;
        }
        if (findstr != "") {
            std::vector<char> corestr;
            corestr.resize(std::max(size_t(4096UL), findstr.size() * 4));
            for (size_t in, memPos = segment.start, corestrPos = 0; memPos < segment.end; memPos += in) {
                size_t freeCorestr = corestr.size() - corestrPos;
                size_t remainingSegment = segment.end - memPos;
                size_t readsize = std::min(remainingSegment, freeCorestr);
                in = process->io->read(memPos, readsize, corestr.data() + corestrPos);
                assert(in == readsize);
                corestrPos += in;
                for (auto found = corestr.begin();; ++found) {
                    found = std::search(corestr.begin(), corestr.begin() + corestrPos, findstr.begin(), findstr.end());
                    if (found == corestr.end())
                        break;
                    IOFlagSave _(cout);
                    std::cout << "0x" << hex << memPos + (found - corestr.begin()) << "\n";
                }
                if (corestrPos >= findstr.size()) {
                    memmove(corestr.data(),
                            corestr.data() + corestrPos - findstr.size() + 1,
                            findstr.size() - 1);
                }
                memPos += in;
            }
        } else {
            auto search = [&](auto m) {
                const size_t step = sizeof(Elf::Off);
                const size_t chunk_size = 1'048'576;
                Elf::Addr loc=segment.start;
                const Elf::Addr end_loc = segment.end;
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
    }
    auto histogram = store.flatten();
    sort(histogram.begin(), histogram.end(),
      [](const ListedSymbol &l, const ListedSymbol &r) { return l.count > r.count; });

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
