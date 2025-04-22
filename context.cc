// vim: expandtab:ts=4:sw=4

#include "libpstack/context.h"
#include "libpstack/dwarf.h"
#include "libpstack/stringify.h"
#include "libpstack/reader.h"

#include <string.h>
#include <unistd.h>
#include <ranges>

#ifdef DEBUGINFOD
#include <elfutils/debuginfod.h>
#endif

namespace pstack {

void Context::DidClose::operator() ( [[maybe_unused]] struct debuginfod_client *client )
{
#ifdef DEBUGINFOD
    if (client)
        debuginfod_end( client );
#endif
}

Context::Context()
    : debug(&std::cerr), output(&std::cout)
{

}

std::shared_ptr<Dwarf::Info>
Context::getDwarf(const std::string &filename)
{
    return getDwarf(getImage(filename));
}

debuginfod_client *
Context::debuginfod()
{
#ifdef DEBUGINFOD
    if (options.noDebuginfod)
        return nullptr;
    if (!debuginfod_)
        debuginfod_ = std::unique_ptr<debuginfod_client, DidClose>(debuginfod_begin());
    return (*debuginfod_).get();
#else
    return nullptr;
#endif
}


std::shared_ptr<Dwarf::Info>
Context::getDwarf(const Elf::BuildID &bid)
{
    return getDwarf(getImage(bid));
}

Dwarf::Info::sptr
Context::getDwarf(Elf::Object::sptr object)
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

/*
 * Find an image keyed by 'key' in container
 */
template <typename Container>
std::optional<std::shared_ptr<Elf::Object>>
Context::getImageIfLoaded(const Container &ctr, const typename Container::key_type &key) {
    counters.elfLookups++;
    auto it = ctr.find(key);
    if (it != ctr.end()) {
        counters.elfHits++;
        if (verbose > 0)
            *debug << "cache hit for ELF image " << key << "\n";
        return it->second;
    }
    if (verbose > 0)
        *debug << "cache miss for ELF image " << key << "\n";
    return {};
}

/*
 * Find an image from a name, caching in container, and using "paths" as potential prefixes for name
 */
std::shared_ptr<Elf::Object>
Context::getImageInPath(const std::vector<std::string> &paths, NameMap &container, const std::string &name, bool isDebug) {
    std::optional<Elf::Object::sptr> cached = getImageIfLoaded(container, name);
    if (cached)
        return *cached;

    Elf::Object::sptr res;
    for (const auto &dir : paths) {
        try {
            res = std::make_shared<Elf::Object>(*this, std::make_shared<MmapReader>(*this, stringify(dir, "/", name)) , isDebug);
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
Context::getImage(const std::string &name) {
    return getImageInPath(exePrefixes, imageByName, name, false);
}

/*
 * get an image, given its build ID. It may be a debug image, or an
 * "executable". We first defer to the filesystem, using the string versions of
 * "getImage", and a broken-down form of the build id, with the first octet of
 * the build-id being a directlry name, and the remainder being the filename,
 * with a possible suffix. This allows us to find things of the form
 * /usr/lib/debug/build-id/NN/NNNNNNNNNNNNNNNNNNNN.debug for example.  The
 * passed "Finder" will be the debuginfod function to fetch either debuginfo or
 * executable info.
 */

std::shared_ptr<Elf::Object>
Context::getImageImpl(
        Context::IdMap &container,
        Context::NameMap &nameContainer,
        const std::vector<std::string> &paths,
        const Elf::BuildID &bid,
        bool isDebug) {
    if (!bid)
        return nullptr;
    std::optional<Elf::Object::sptr> cached = getImageIfLoaded( container, bid );
    if (cached)
        return *cached;

    std::string bidpath = stringify(
            AsHex(bid[0]),
            "/",
            AsHex(std::views::all(bid) | std::views::drop(1)),
            isDebug ? ".debug" : "");

    Elf::Object::sptr res = getImageInPath(paths, nameContainer, bidpath, isDebug);
#ifdef DEBUGINFOD
    if (!res && debuginfod()) {
        char *path;
        int fd = (isDebug ? debuginfod_find_debuginfo : debuginfod_find_executable)(debuginfod(), bid.data(), int( bid.size() ), &path);
        if (fd >= 0) {
            // Wrap the fd in a reader, and then a cache reader...
            std::shared_ptr<Reader> reader = std::make_shared<FileReader>(*this, path, fd );
            reader = std::make_shared<CacheReader>(reader);
            // and then wrap the lot in an ELF object.
            res = std::make_shared<Elf::Object>( *this, reader, true );
            free(path);
            if (verbose)
                *debug << "fetched " << *res->io << " for " << bid << " with debuginfod\n";
        } else if (verbose) {
            *debug << "failed to fetch image for " << bid << " with debuginfod: " << strerror(-fd) << "\n";
        }
    }
    container[bid] = res; // cache it.
#endif
    return res;
}

std::shared_ptr<Elf::Object>
Context::getDebugImage(const std::string &name) {
    return getImageInPath(debugPrefixes, debugImageByName, name, true);
}

#ifndef DEBUGINFOD
// dummy functions in case we have no debuginfod.
namespace {
int debuginfod_find_debuginfo (debuginfod_client *, const unsigned char *, int, char **) { return -ENOSYS; }
int debuginfod_find_executable (debuginfod_client *, const unsigned char *, int, char **) { return -ENOSYS; }
}
#endif

std::shared_ptr<Elf::Object>
Context::getDebugImage(const Elf::BuildID &bid) {
    return getImageImpl(debugImageByID, debugImageByName, debugBuildIdPrefixes, bid, true);
}

std::shared_ptr<Elf::Object>
Context::getImage(const Elf::BuildID &bid) {
    return getImageImpl(imageByID, imageByName, exeBuildIdPrefixes, bid, false);
}

std::shared_ptr<const Reader>
Context::loadFile(const std::string &path) {
    return std::make_shared<CacheReader>( std::make_shared<FileReader>(*this, path));
}

std::string
Context::dirname(const std::string &in)
{
    auto it = in.rfind('/');
    if (it == std::string::npos)
        return ".";
    return in.substr(0, it);
}

std::string
Context::basename(const std::string &in)
{
    auto it = in.rfind('/');
    auto out =  it == std::string::npos ?  in : in.substr(it + 1);
    return out;
}

std::string
Context::linkResolve(std::string name)
{
    char buf[1024];
    std::string orig = name;
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
Context::openFileDirect(const std::string &name_, int mode, int mask)
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

std::string
Context::procname(pid_t pid, const std::string &base)
{
    return linkResolve(stringify("/proc/", pid, "/", base));
}

int
Context::openfile(const std::string &name, int mode, int mask)
{
    int fd = -1;
    for (auto &r : pathReplacements) {
       if (name.compare(0, r.first.size(), r.first) == 0) {
          fd = openFileDirect(r.second + std::string(name, r.first.size()), mode, mask);
          if (fd != -1)
             return fd;
       }
    }
    fd = openFileDirect(name, mode, mask);
    if (fd != -1)
       return fd;
    throw (Exception() << "cannot open file '" << name << "': " << strerror(errno));
}

}
