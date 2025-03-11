#pragma once
#include <map>
#include <string_view>
#include <memory>
#include <vector>
#ifdef DEBUGINFOD
#include <elfutils/debuginfod.h>
#endif
#include <limits>
#include <fcntl.h>

namespace pstack {
class Reader;

namespace Elf {
class Object;
}

namespace Dwarf {
class Info;
}

struct PstackOptions {
    bool nosrc = false; // don't display source code (makes things faster)
    bool doargs = false; // show arguments to functions
    bool dolocals = false;
    bool nothreaddb = false; // don't use threaddb.
    bool nodienames = false; // don't use names from DWARF dies in backtraces.
    bool noExtDebug = false; // if set, don't look for exernal ELF info, i.e., usinb debuglink, or buildid.
#ifdef DEBUGINFOD
    bool doDebuginfod = true; // if set, don't look for exernal ELF info, i.e., usinb debuglink, or buildid.
#endif
    int maxdepth = std::numeric_limits<int>::max();
    int maxframes = 20;
};

class Context {
   std::map<std::shared_ptr<Elf::Object>, std::shared_ptr<Dwarf::Info>> dwarfCache;
   std::map<std::string, std::shared_ptr<Elf::Object>> elfCache;
   std::vector<std::string> debugDirectories;
public:
   void addDebugDirectory(std::string_view dir) {
      debugDirectories.emplace_back(dir);
   }
   std::ostream *debug{};
   std::ostream *output{};
   PstackOptions options{};
#ifdef DEBUGINFOD
   struct DidClose {
      void operator() ( debuginfod_client *client ) {
         debuginfod_end( client );
      }
   };
   std::unique_ptr<debuginfod_client, DidClose> debuginfod;
#endif
   int verbose{};
   std::vector<std::pair<std::string, std::string>> pathReplacements;
   std::string dirname(const std::string &);
   std::string basename(const std::string &);
   std::string linkResolve(std::string name);
   int openfile(const std::string &filename, int mode = O_RDONLY, int umask = 0777);
   int openFileDirect(const std::string &name_, int mode, int mask);
   std::shared_ptr<Elf::Object> getImageForName(const std::string &name, bool isDebug = false);
   std::shared_ptr<Elf::Object> getImageIfLoaded(const std::string &name);
   std::shared_ptr<Elf::Object> getDebugImage(const std::string &name);
   std::shared_ptr<Dwarf::Info> getDwarf(const std::string &);
   std::shared_ptr<Dwarf::Info> getDwarf(std::shared_ptr<Elf::Object>);
   void flush(std::shared_ptr<Elf::Object> o);
   std::string procname(pid_t pid, const std::string &base);

   std::shared_ptr<const Reader> loadFile(const std::string &path);
   Context();
   Context(const Context &) = delete;
   Context(Context &&) = delete;
   Context &operator = (const Context &) = delete;
   Context &operator = (Context &&) = delete;
   ~Context() noexcept;
};

}
