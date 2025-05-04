/*
 * Canal searches through core files looking for references to symbols.  The
 * symbols can be provided by a glob style pattern, and defaults to a pattern
 * that matches symbols associated with vtables.  So, by default, canal finds
 * likely instances of classes with virtual methods in the process's address
 * space, and can be useful to help identify memory leaks.
 */

#include <unistd.h>
#include <assert.h>
#include <iostream>
#include <exception>
#include <algorithm>
#include <sys/types.h>
#include <map>
#include <err.h>

#include "libpstack/context.h"
#include "libpstack/proc.h"
#include "libpstack/elf.h"
#include "libpstack/dwarf.h"
#include "libpstack/stringify.h"
#include "libpstack/ioflag.h"
#include "libpstack/flags.h"
#if defined( WITH_PYTHON3 )
#define WITH_PYTHON
#endif
#ifdef WITH_PYTHON
#include "libpstack/python.h"
#include <Python.h>
#endif

using namespace std;
using namespace pstack;

using AddressRanges = std::vector<std::pair<Elf::Off, Elf::Off>>;
#ifdef WITH_PYTHON
std::unique_ptr<PythonPrinter<3>> py = nullptr;
#endif

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

static void findString(const Procman::Process &process,
      const Procman::AddressRange &segment,
      const std::string &findstr) {
   std::vector<char> corestr;
   corestr.resize(std::max(size_t(4096UL), findstr.size() * 4));
   for (size_t in, memPos = segment.start, corestrPos = 0; memPos < segment.end; memPos += in) {
      size_t freeCorestr = corestr.size() - corestrPos;
      size_t remainingSegment = segment.fileEnd - memPos;
      size_t readsize = std::min(remainingSegment, freeCorestr);
      in = process.io->read(memPos, readsize, corestr.data() + corestrPos);
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
}

template <typename Matcher, typename Word> inline void search(
        const Reader::csptr &view,
        const Matcher & m,
        Elf::Addr loc,
        const AddressRanges &searchaddrs,
        SymbolStore &store,
        bool showaddrs) {
    try {
        IOFlagSave _(cout);
        ReaderArray<Word, 131072> r(*view, 0);
        auto start = r.begin();
        if (searchaddrs.size()) {
            for (auto cur = start; cur != r.end(); ++cur) {
                Word p = *cur;
                for (const auto &range : searchaddrs )
                    if (p >= range.first && p < range.second)
                        cout << "0x" << hex << loc + (cur - start) * sizeof( Word) << dec << "\n";
            }
        } else {
            for (auto cur = start; cur != r.end(); ++cur) {
                Word p = *cur;
                if ( auto [ found, sym ] = store.find(p, m); found) {
                    if (showaddrs)
                        cout
                            << sym->name << " 0x" << std::hex << loc + (cur - start) * sizeof(Word)
                            << std::dec <<  " ... size=" << sym->sym.st_size
                            << ", diff=" << p - sym->memaddr() << endl;
#ifdef WITH_PYTHON
                    if (py) {
                        std::cout << "pyo " << Elf::Addr(loc) << " ";
                        py->print(Elf::Addr(loc) - sizeof (PyObject) +
                                sizeof (struct _typeobject *));
                        std::cout << "\n";
                    }
#endif
                    sym->count++;
                }
            }
        }
    } catch (const std::exception &ex) {
        std::clog << "warning: error reading data at " << std::hex << loc << std::dec << ": " << ex.what() << "\n";
    }
}

template <typename Matcher> void search(int wordsize,
        Procman::Process &process,
        const Matcher & m, const Procman::AddressRange &segment,
        const AddressRanges &searchaddrs, SymbolStore &store, bool showaddrs) {
    auto view = process.io->view( "segment view", segment.start, segment.fileEnd - segment.start );
    if (wordsize == 32) {
        return search<Matcher, uint32_t>(view, m, segment.start, searchaddrs, store, showaddrs);
    } else if (wordsize == 64) {
        return search<Matcher, uint64_t>(view, m, segment.start, searchaddrs, store, showaddrs);
    } else {
        errx(1, "invalid word size %d, must be 32 or 64", wordsize);
    }
}

int
mainExcept(int argc, char *argv[])
{
    Context context;
    std::vector<std::string> patterns;
    Elf::Object::sptr exec;
    int wordsize = sizeof (Elf::Off) * 8;
    Elf::Object::sptr core;
    bool showaddrs = false;
    bool showsyms = false;

    AddressRanges searchaddrs;
    std::string findstr;
    int symOffset = -1;
#ifdef WITH_PYTHON
    bool doPython = false;
#endif

    Flags flags;

    flags
#ifdef WITH_PYTHON
    .add("python", 'P', "try to find python objects", Flags::setf(doPython))
#endif
    .add("show-syms", 'V', "show symbols matching search pattern", Flags::setf(showsyms))
    .add("show-addrs", 's', "show adddress of references found in core", Flags::setf(showaddrs))
    .add("verbose", 'v', "increase verbosity (may be repeated)", [&]() { ++context.verbose; })
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
             context.pathReplacements.push_back(std::make_pair(both.substr(0, colon), both.substr(colon + 1)));
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
    .add("wordsize", 'w', "wordsize(16 or 32)", "consider address ranges as wordsize-bit values", Flags::set( wordsize ) )
    .add("string", 'S', "text", "search the core for the text string <text>, and print it's address", Flags::set(findstr))
    .parse(argc, argv);

    if (argc - optind >= 2) {
        exec = context.getImage(argv[optind]);
        optind++;
    }


    if (argc - optind < 1) {
        clog << Usage(flags);
        return 0;
    }

    auto process = Procman::Process::load(context, exec, argv[optind]);

#ifdef WITH_PYTHON
    PyInterpInfo info;
    if (doPython) {
       info = getPyInterpInfo(*process);
       py = make_unique<PythonPrinter<3>>(*process, std::cout, info);
    }
#endif
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
        auto findSymbols = [&]( auto table ) {
           for (const auto &sym : *table) {
               for (auto &pattern : patterns) {
                   auto name = table->name(sym);
                   if (globmatch(pattern, name)) {
                       store.add(ListedSymbol(sym, loaded.first, name, loaded.second.name()));
                       if (context.verbose > 1 || showsyms)
                          std::cout << name << "\n";
                       count++;
                   }
               }
           }
        };
        auto obj = loaded.second.object(process->context);
        findSymbols( obj->dynamicSymbols() );
        findSymbols( obj->debugSymbols() );
        if (context.verbose)
            *context.debug << "found " << count << " symbols in " << *obj->io << endl;
    }
    if (showsyms)
       exit(0);

    // Now run through the corefile, searching for virtual objects.
    auto as = process->addressSpace();
    for (auto &segment : as ) {
        if (context.verbose) {
            IOFlagSave _(*context.debug);
            *context.debug << "scan " << hex << segment.start <<  " to " << segment.start + segment.fileEnd;
        }
        if (segment.vmflags.find( pstack::Procman::AddressRange::VmFlag::memory_mapped_io ) != segment.vmflags.end() ) {
           if (context.verbose) {
              *context.debug << "skipping IO mapping\n";
           }
           continue;
        }
        if (findstr != "") {
           findString( *process, segment, findstr );
        } else {
            if (symOffset > 0)
                search<OffsetBoundSymbolMatcher>(wordsize, *process,
                      OffsetBoundSymbolMatcher(symOffset),
                      segment, searchaddrs, store, showaddrs);
            else
                search<OffsetFreeSymbolMatcher>(wordsize, *process,
                      OffsetFreeSymbolMatcher(),
                      segment, searchaddrs, store, showaddrs);
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
