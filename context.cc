// vim: expandtab:ts=4:sw=4

#include "libpstack/context.h"
#include "libpstack/dwarf.h"
#include "libpstack/reader.h"

#include <string.h>
#include <unistd.h>
#include <filesystem>
#include <ranges>

#include <dlfcn.h>
#include <stdexcept>

namespace pstack {

// If requested, we will attempt to dynamically load the debuginfod API from
// libdebuginfod.so.1
namespace {
struct DebuginfodRuntime {
    template <typename callable_t> struct LoadFunc {
        callable_t callable;
        LoadFunc(void *lib, const char *funcname) : callable{callable_t(dlsym(lib, funcname))} {
            if (!callable) {
                throw std::runtime_error(stringify("failed to find '", funcname, "': ", dlerror()));
            }
        }
        template <typename ...Args> auto operator()(Args...args) const { return (*callable)(std::forward<Args>(args)...); }
    };

    static void *dlopenOrThrow(const char *p, int flags) {
        void *lib = dlopen(p, flags);
        if (!lib)
            throw std::runtime_error(stringify("failed to load library '", p, "': ", dlerror()));
        return lib;
    }

    void *lib;
    LoadFunc<debuginfod_client *(*)(void)> begin;
    LoadFunc<void (*)(debuginfod_client *)> end;
    LoadFunc<int (*)(debuginfod_client *, const unsigned char *, int, char ** )> find_debuginfo;
    LoadFunc<int (*)(debuginfod_client *, const unsigned char *, int, char ** )> find_executable;
    LoadFunc<int (*)(debuginfod_client *, const unsigned char *, int, char ** )> find_source;
    LoadFunc<int (*)(debuginfod_client *, const unsigned char *, int, const char *, char **)> find_section;
    using debuginfod_progressfn_t = int (*)(debuginfod_client *, long, long);
    LoadFunc<int (*)(debuginfod_client *, debuginfod_progressfn_t )> set_progressfn;
    LoadFunc<void (*)(debuginfod_client *, int)> set_verbose_fd;
    LoadFunc<void (*)(debuginfod_client *, void *)> set_user_data;
    LoadFunc<void*(*)(debuginfod_client *)> get_user_data;
    LoadFunc<char* (*)(debuginfod_client *)> get_url;
    LoadFunc<int (*)(debuginfod_client *, const char* )> add_http_header;
    LoadFunc<const char* (*)(debuginfod_client *)> get_headers;

    DebuginfodRuntime()
        : lib(dlopenOrThrow("libdebuginfod.so.1", RTLD_NOW))
          , begin(lib, "debuginfod_begin")
          , end(lib, "debuginfod_end")
          , find_debuginfo(lib, "debuginfod_find_debuginfo")
          , find_executable(lib, "debuginfod_find_executable")
          , find_source(lib, "debuginfod_find_source")
          , find_section(lib, "debuginfod_find_section")
          , set_progressfn(lib, "debuginfod_set_progressfn")
          , set_verbose_fd(lib, "debuginfod_set_verbose_fd")
          , set_user_data(lib, "debuginfod_set_user_data")
          , get_user_data(lib, "debuginfod_get_user_data")
          , get_url(lib, "debuginfod_get_url")
          , add_http_header(lib, "debuginfod_add_http_header")
          , get_headers(lib, "debuginfod_get_headers")
    { }
    static DebuginfodRuntime *create() {
        try {
            return new DebuginfodRuntime();
        }
        catch (const std::exception &ex) {
            std::cerr << "failed to load debuginfod: " << ex.what() << "\n";
            return nullptr;
        }
    }
};

const DebuginfodRuntime *debuginfod() { 
    static DebuginfodRuntime *once = DebuginfodRuntime::create();
    return once;
}
}

void Context::DidClose::operator() ( [[maybe_unused]] struct debuginfod_client *client )
{
    if (client)
        debuginfod()->end( client );
}

Context::Context()
    : debug(&std::cerr), output(&std::cout)
{

}

std::shared_ptr<Dwarf::Info>
Context::findDwarf(const std::filesystem::path &filename)
{
    return findDwarf(findImage(filename));
}

debuginfod_client *
Context::getDebuginfodClient()
{
    if (!options.withDebuginfod || debuginfod() == nullptr)
        return nullptr;
    if (!debuginfodClient_) {
        debuginfodClient_ = std::unique_ptr<debuginfod_client, DidClose>(debuginfod()->begin());
        if (debuginfodClient_ && isatty(2)) {
            debuginfod()->set_progressfn( debuginfodClient_->get(),
                    [] (debuginfod_client *client, long num, long denom) {
                        int *progress = (int *)debuginfod()->get_user_data(client);
                        ++*progress;
                        const char *url =  debuginfod()->get_url( client );
                        if (url == nullptr)
                            url = "<unknown>";
                        std::cerr << "debuginfod download " << url << ". progress: "
                            << (denom ? num * 100 / denom : 0) << "%"
                            << " (" << num << " of " << denom << ")" << "\r";
                            return 0; });
        }
    }
    return (*debuginfodClient_).get();
}

std::shared_ptr<Dwarf::Info>
Context::findDwarf(const Elf::BuildID &bid)
{
    return findDwarf(findImage(bid));
}

Dwarf::Info::sptr
Context::findDwarf(Elf::Object::sptr object)
{
    auto it = dwarfCache.find(object);
    counters.dwarfLookups++;
    if (it != dwarfCache.end()) {
        counters.dwarfHits++;
        return it->second;
    }
    auto dwarf = std::make_shared<Dwarf::Info>(object);
    dwarfCache[object] = dwarf;
    return dwarf;
}

Context::~Context() noexcept {
    if (verbose >= 2) {
        *debug << "DWARF image cache: lookups: " << counters.dwarfLookups << ", hits=" << counters.dwarfHits << "\n"
            << "ELF image cache: lookups: " << counters.elfLookups << ", hits=" << counters.elfHits << "\n"
            << "executable images by name:\n";

        auto dumpcache = [&] (const auto &map, const char *descr) {
            *debug << descr << "\n";
            for (const auto &[name, elf] : map) {
                *debug << "\t" << name << ": ";
                if (elf)
                    *debug << *elf->io;
                else
                    *debug << "(negative cache entry)";
                *debug << "\n";
            }
        };

        dumpcache( imageByName, "executables by name");
        dumpcache( debugImageByName, "debuginfo by name");
        dumpcache( imageByID, "executables by build-id");
        dumpcache( debugImageByID, "debuginfo by build-id");
    }
}

void
Context::flush(std::shared_ptr<Elf::Object> o)
{
    // Flush references to "o" out of any caches.
    auto flushmap = [&o](auto &map) {
        for (auto it = map.begin(), next = it; it != map.end(); it = next) {
            if (it->second == o)
                next = map.erase(it);
            else
                next = std::next( it );
        }
    };
    flushmap(imageByName);
    flushmap(debugImageByName);
    flushmap(imageByID);
    flushmap(debugImageByID);
    dwarfCache.erase(o);
}

// pretty-printer for key types.
template <typename T> struct ContainerKeyDescr{};
std::ostream &operator << (std::ostream &os, const ContainerKeyDescr<std::filesystem::path> &) { return os << "path"; }
std::ostream &operator << (std::ostream &os, const ContainerKeyDescr<std::string> &) { return os << "string"; }
std::ostream &operator << (std::ostream &os, const ContainerKeyDescr<Elf::BuildID> &) { return os << "build-id"; }
/*
 * Find an image keyed by 'key' in container
 */

template <typename Container>
std::optional<std::shared_ptr<Elf::Object>>
Context::getImageIfLoaded(const Container &ctr, const typename Container::key_type &key, bool isDebug) {
    counters.elfLookups++;
    auto it = ctr.find(key);
    if (it != ctr.end()) {
        counters.elfHits++;
        if (verbose > 0)
            *debug << "cache hit for " << (isDebug?"debug ":"") << "ELF image with " << ContainerKeyDescr<typename Container::key_type>{} << " " << key << "\n";
        return it->second;
    }
    if (verbose > 0)
        *debug << "cache miss for " << (isDebug?"debug ":"") << "ELF image with " << ContainerKeyDescr<typename Container::key_type>{} << " " << key << "\n";
    return {};
}

std::shared_ptr<Elf::Object>
Context::openImage(const std::filesystem::path &path, int fd, bool isDebug) {
    return std::make_shared<Elf::Object>(*this, std::make_shared<MmapReader>(*this, path, fd) , isDebug);
}

/*
 * Find an image from a name, caching in container, and using "paths" as potential prefixes for name
 */
std::shared_ptr<Elf::Object>
Context::getImageInPath(const std::vector<std::filesystem::path> &paths, NameMap &container, const std::filesystem::path &name, bool isDebug, bool resolveLink) {
    std::optional<Elf::Object::sptr> cached = getImageIfLoaded(container, name, isDebug);
    if (cached)
        return *cached;

    Elf::Object::sptr res;
    // Walk through these backwards - prefer user specified values to defaults.
    for (const auto &dir : std::views::reverse(paths)) {
        auto path = dir/name;
        if (resolveLink) {
            std::array<char, PATH_MAX> buf;
            char *p = realpath( path.c_str(), buf.data() );
            if (p != nullptr) {
                path = p;
            } else if (errno == ENOENT) {
                return nullptr;
            } else {
                *debug << "failed to resolve " << path << ": " << strerror_r(errno, buf.data(), buf.size()) << "\n";
            }
        }
        try {
            res = openImage( path, -1, isDebug );
            break;
        }
        catch (const std::exception &ex) {
            continue;
        }
    }
    if (verbose > 0) {
        if (res)
            *debug << "found " << *res->io << " for " << name << " in one of " << json(paths) << "\n";
        else
            *debug << "no image found for " << name << " in any of " << json(paths) << "\n";
    }
    container[name] = res;
    return res;
}

/*
 * get an image from a filename
 */
std::shared_ptr<Elf::Object>
Context::findImage(const std::filesystem::path &name) {
    if (options.noLocalFiles)
        return nullptr;
    return getImageInPath(exePrefixes, imageByName, name, false, false);
}

/*
 * get an image, given its build ID. It may be a debug image, or an
 * "executable". We first defer to the filesystem, using the string versions of
 * "findImage", and a broken-down form of the build id, with the first octet of
 * the build-id being a directlry name, and the remainder being the filename,
 * with a possible suffix. This allows us to find things of the form
 * /usr/lib/debug/build-id/NN/NNNNNNNNNNNNNNNNNNNN.debug for example.  The
 * passed "Finder" will be the debuginfod function to fetch either debuginfo or
 * executable info.
 */

std::shared_ptr<Elf::Object> Context::getImageImpl( const Elf::BuildID &bid, bool isDebug) {

    Elf::Object::sptr res;
    if (!bid || options.noBuildIds)
        return nullptr;
    IdMap &container = isDebug ? debugImageByID : imageByID;

    std::optional<Elf::Object::sptr> cached = getImageIfLoaded( container, bid, isDebug );
    if (cached)
        return *cached;

    if (!options.noLocalFiles) {
        NameMap &nameContainer = isDebug ? debugImageByName : imageByName;
        std::vector<std::filesystem::path> &paths = isDebug ? debugBuildIdPrefixes : exeBuildIdPrefixes;

        std::stringstream bucket;
        bucket << AsHex{bid[0]};
        std::stringstream rest;
        rest << AsHex{std::views::all(bid) | std::views::drop(1)};
        if ( isDebug )
            rest << ".debug";

        std::filesystem::path bidpath = std::filesystem::path( bucket.str() ) / std::filesystem::path( rest.str() );
        res = getImageInPath(paths, nameContainer, bidpath, isDebug, true);
    }
    if (!res && getDebuginfodClient()) {
        char *path = nullptr;
        int progress = 0;
        debuginfod()->set_user_data(getDebuginfodClient(), &progress);
        int fd = (isDebug ? debuginfod()->find_debuginfo : debuginfod()->find_executable)
            (getDebuginfodClient(), bid.data(), int( bid.size() ), &path);
        if (progress > 0) {
            // If we reported progress at least once, move to the next line
            std::cerr << "\n";
        }
        if (fd >= 0) {
            res = openImage( path, fd, true );
            free(path);
            if (verbose)
                *debug << "fetched " << *res->io << " for " << bid << " with debuginfod\n";
        } else if (verbose) {
            *debug << "failed to fetch image for " << bid << " with debuginfod: " << strerror(-fd) << "\n";
        }
    }
    container[bid] = res; // cache it.
    return res;
}

std::shared_ptr<Elf::Object>
Context::findDebugImage(const std::filesystem::path &name) {
    return getImageInPath(debugPrefixes, debugImageByName, name, true, false);
}

std::shared_ptr<Elf::Object> Context::findDebugImage(const Elf::BuildID &bid) { return getImageImpl(bid, true); }
std::shared_ptr<Elf::Object> Context::findImage(const Elf::BuildID &bid) { return getImageImpl(bid, false); }

std::shared_ptr<const Reader>
Context::loadFile(const std::filesystem::path &path) {
    return std::make_shared<CacheReader>( std::make_shared<FileReader>(*this, path));
}

std::filesystem::path
Context::linkResolve(const std::filesystem::path &path)
{
    std::string name = path;
    char buf[1024];
    auto orig = name;
    int rc;
    for (;;) {
        rc = readlink(name.c_str(), buf, sizeof buf - 1);
        // some files in /proc are links, but report "(deleted)" in the name if
        // the original has gone away. Opening such files works, and uses the
        // in-core inode, so use that if we can
        if (rc == -1) {
            return errno == EINVAL ? name : orig;
        }
        buf[rc] = 0;
        if (buf[0] != '/') {
            auto lastSlash = name.rfind('/');
            name = lastSlash == std::string::npos
               ? std::string(buf)
               : name.substr(0, lastSlash + 1) + std::string(buf);
        } else {
            name = buf;
        }
    }
    return name;
}

int
Context::openFileDirect(const std::filesystem::path &name_, int mode, int mask)
{
    auto fd = ::open(name_.c_str(), mode, mask);
    if (verbose > 2) {
       if (fd != -1)
          *debug << "opened " << name_ << ", fd=" << fd << "\n";
       else
          *debug << "failed to open " << name_ << ": " << strerror(errno) << "\n";
    }
    return fd;
}

std::filesystem::path
Context::procname(pid_t pid, const std::filesystem::path &base)
{
    return linkResolve(std::filesystem::path( "/proc" ) 
            / std::to_string( pid ) / base);
}

int
Context::openfile(const std::filesystem::path &name, int mode, int mask)
{
    int fd = openFileDirect(name, mode, mask);
    if (fd != -1)
       return fd;
    throw (Exception() << "cannot open file '" << name << "': " << strerror(errno));
}

}
