#pragma once
#include <map>
#include <string_view>
#include <memory>
#include <vector>
#include <optional>
#include <limits>
#include <optional>
#include <fcntl.h>

struct debuginfod_client;

namespace pstack {

struct Options {
    bool nosrc = false; // don't display source code (makes things faster)
    bool doargs = false; // show arguments to functions
    bool dolocals = false;
    bool nothreaddb = false; // don't use threaddb.
    bool nodienames = false; // don't use names from DWARF dies in backtraces.
    bool noExtDebug = false; // don't look for exernal ELF info, i.e., using debuglink, or buildid.
    bool noDebuginfod = false; // don't use debuginfod client library.
    int maxdepth = std::numeric_limits<int>::max();
    int maxframes = 30;
};

class Reader;
namespace Elf {
class Object;
class BuildID;
}

namespace Dwarf {
class Info;
}

class Context {
   std::map<std::shared_ptr<Elf::Object>, std::shared_ptr<Dwarf::Info>> dwarfCache;

   using NameMap = std::map<std::string, std::shared_ptr<Elf::Object>>;
   using IdMap = std::map<Elf::BuildID, std::shared_ptr<Elf::Object>>;

   NameMap imageByName;
   NameMap debugImageByName;
   IdMap imageByID;
   IdMap debugImageByID;
   struct {
      int dwarfLookups;
      int elfLookups;
      int dwarfHits;
      int elfHits;
   } counters {};
   template <typename Container> std::optional<std::shared_ptr<Elf::Object>> getImageIfLoaded(const Container &ctr, const typename Container::key_type &key);
   std::shared_ptr<Elf::Object> getImageInPath(const std::vector<std::string> &paths, NameMap &container, const std::string &name, bool debug);
   std::shared_ptr<Elf::Object> getImageImpl( IdMap &container, NameMap &nameContainer, const std::vector<std::string> &paths, const Elf::BuildID &bid, bool isDebug);

   struct DidClose {
      void operator() ( struct debuginfod_client *client );
   };
   std::optional<std::unique_ptr<debuginfod_client, DidClose>> debuginfod_;
   debuginfod_client *debuginfod();


public:
   std::vector<std::string> debugPrefixes { "/usr/lib/debug", "/usr/lib/debug/usr" };
   std::vector<std::string> debugBuildIdPrefixes { "/usr/lib/debug/.build-id" };
   std::vector<std::string> exePrefixes { "" };
   std::vector<std::string> exeBuildIdPrefixes { "/usr/lib/.build-id" };  // we could add the debuginfod cache here?
   std::ostream *debug{};
   std::ostream *output{};
   Options options{};
   int verbose{};
   std::vector<std::pair<std::string, std::string>> pathReplacements;
   std::string dirname(const std::string &);
   std::string basename(const std::string &);
   std::string linkResolve(std::string name);
   int openfile(const std::string &filename, int mode = O_RDONLY, int umask = 0777);
   int openFileDirect(const std::string &name_, int mode, int mask);

   std::shared_ptr<Elf::Object> getImage(const std::string &name);
   std::shared_ptr<Elf::Object> getImage(const Elf::BuildID &);

   // Debug images are specifically those with the text/data stripped, and just
   // the Dwarf/symbol table left.
   std::shared_ptr<Elf::Object> getDebugImage(const std::string &name);
   std::shared_ptr<Elf::Object> getDebugImage(const Elf::BuildID &);

   std::shared_ptr<Dwarf::Info> getDwarf(const std::string &);
   std::shared_ptr<Dwarf::Info> getDwarf(const Elf::BuildID &);

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
