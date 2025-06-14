#pragma once
#include <map>
#include <memory>
#include <vector>
#include <filesystem>
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
    bool withDebuginfod = false; // use debuginfod client library.
    bool noBuildIds = false;
    bool noLocalFiles = false;
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

   using NameMap = std::map<std::filesystem::path, std::shared_ptr<Elf::Object>>;
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
   template <typename Container> std::optional<std::shared_ptr<Elf::Object>> getImageIfLoaded(const Container &ctr, const typename Container::key_type &key, bool isDebug);
   std::shared_ptr<Elf::Object> getImageInPath(const std::vector<std::filesystem::path> &paths, NameMap &container, const std::filesystem::path &name, bool isDebug, bool resolveLinks);
   std::shared_ptr<Elf::Object> getImageImpl( const Elf::BuildID &bid, bool isDebug);

   struct DidClose { void operator() ( struct debuginfod_client *client ); };
   std::optional<std::unique_ptr<debuginfod_client, DidClose>> debuginfod_;
   debuginfod_client *debuginfod();

public:
   std::vector<std::filesystem::path> debugPrefixes { "/usr/lib/debug", "/usr/lib/debug/usr" };
   std::vector<std::filesystem::path> debugBuildIdPrefixes { "/usr/lib/debug/.build-id" };
   std::vector<std::filesystem::path> exePrefixes { "" };
   std::vector<std::filesystem::path> exeBuildIdPrefixes { "/usr/lib/.build-id" };  // we could add the debuginfod cache here?
   std::ostream *debug{};
   std::ostream *output{};
   Options options{};
   int verbose{};
   std::filesystem::path linkResolve(const std::filesystem::path &name);
   int openfile(const std::filesystem::path &filename, int mode = O_RDONLY, int umask = 0777);
   int openFileDirect(const std::filesystem::path &name_, int mode, int mask);

   // Unlike getImage, this will not search paths - name must be a local file path.
   std::shared_ptr<Elf::Object> openImage(const std::filesystem::path &name, int fd = -1, bool isDebug = false);

   // Get an image, searching as required.
   std::shared_ptr<Elf::Object> findImage(const std::filesystem::path &name);
   std::shared_ptr<Elf::Object> findImage(const Elf::BuildID &);

   // Debug images are specifically those with the text/data stripped, and just
   // the Dwarf/symbol table left.
   std::shared_ptr<Elf::Object> findDebugImage(const std::filesystem::path &name);
   std::shared_ptr<Elf::Object> findDebugImage(const Elf::BuildID &);

   std::shared_ptr<Dwarf::Info> findDwarf(const std::filesystem::path &);
   std::shared_ptr<Dwarf::Info> findDwarf(const Elf::BuildID &);

   std::shared_ptr<Dwarf::Info> findDwarf(std::shared_ptr<Elf::Object>);
   void flush(std::shared_ptr<Elf::Object> o);
   std::filesystem::path procname(pid_t pid, const std::filesystem::path &base);

   std::shared_ptr<const Reader> loadFile(const std::filesystem::path &path);
   Context();
   Context(const Context &) = delete;
   Context(Context &&) = delete;
   Context &operator = (const Context &) = delete;
   Context &operator = (Context &&) = delete;
   ~Context() noexcept;
};

}
