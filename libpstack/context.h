#pragma once
#include <map>
#include <memory>
#include <vector>
#include <limits>
#include <fcntl.h>
#include <iostream>

namespace pstack {
class Reader;

namespace Elf {
class Object;
}

namespace Dwarf {
class Info;
}

struct Options {
    bool nosrc { false }; // don't show source information.
    bool doargs { false }; // show function arguments if possible
    bool dolocals { false }; // show local variables if possible (python only for now)
    bool nothreaddb { false }; // Don't use the threaddb functions
    bool nodienames { false }; // don't use names from DWARF dies in backtraces.
    bool noExtDebug { false }; // if set, don't look for exernal ELF info, i.e., usinb debuglink, or buildid.
    int maxdepth = { std::numeric_limits<int>::max() };
    int maxframes { 20 };
};

// Global state for pstack. Includes configuration options, and caches.
class Context {

   // Cache filename->ELF object
   std::map<std::string, std::shared_ptr<Elf::Object>> elfCache;

   // Cache ELF object -> DWARF info.
   std::map<std::shared_ptr<Elf::Object>, std::shared_ptr<Dwarf::Info>> dwarfCache;

public:
   std::vector<std::string> debugDirectories { "/usr/lib/debug", "/usr/lib/debug/usr" };
   std::ostream *debug{&std::cerr};
   std::ostream *output{&std::cout};
   std::vector<std::pair<std::string, std::string>> pathReplacements;
   Options options;
   int verbose{};

   static std::string dirname(const std::string &);
   static std::string basename(const std::string &);
   static std::string linkResolve(std::string name);
   int openfile(const std::string &filename, int mode = O_RDONLY, int umask = 0777);
   int openFileDirect(const std::string &name_, int mode, int mask);

   // Access cache of ELF and DWARF info.
   std::shared_ptr<Elf::Object> getELF(const std::string &name, bool isDebug = false);
   std::shared_ptr<Elf::Object> getELFIfLoaded(const std::string &name);
   std::shared_ptr<Elf::Object> getDebugImage(const std::string &name);
   std::shared_ptr<Dwarf::Info> getDWARF(const std::string &);
   std::shared_ptr<Dwarf::Info> getDWARF(std::shared_ptr<Elf::Object>);

   void flush(std::shared_ptr<Elf::Object> o);
   std::string procname(pid_t pid, const std::string &base);
   std::shared_ptr<const Reader> loadFile(const std::string &path);
   Context() = default;
   ~Context() = default;
   Context(const Context &) = delete;
   Context(Context &&) = delete;
   Context &operator = (const Context &) = delete;
   Context &operator = (Context &&) = delete;
};

}
