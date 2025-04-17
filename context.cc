// vim: expandtab:ts=4:sw=4

#include "libpstack/context.h"
#include "libpstack/dwarf.h"
#include "libpstack/stringify.h"
#include "libpstack/reader.h"

#include <unistd.h>
#include <string.h>
#ifdef DEBUGINFOD
#include <elfutils/debuginfod.h>
#endif

namespace pstack {

void Context::DidClose::operator() ( [[maybe_unused]] struct debuginfod_client *client )
{
#ifdef DEBUGINFOD
    debuginfod_end( client );
#endif
}

Context::Context()
    : debugDirectories { "/usr/lib/debug", "/usr/lib/debug/usr" }
    , debug(&std::cerr), output(&std::cout)
{
#ifdef DEBUGINFOD
    if (!options.noDebuginfod)
       debuginfod.reset( debuginfod_begin() );
#endif
}

int dwarfLookups, elfLookups, dwarfHits, elfHits;
bool noExtDebug;

std::shared_ptr<Dwarf::Info>
Context::getDwarf(const std::string &filename)
{
    return getDwarf(getImage(filename));
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
    dwarfLookups++;
    if (it != dwarfCache.end()) {
        dwarfHits++;
        return it->second;
    }
    auto dwarf = std::make_shared<Dwarf::Info>(object);
    dwarfCache[object] = dwarf;
    return dwarf;
}

Context::~Context() noexcept {
    if (verbose >= 2) {
        *debug << "image cache: lookups: " << dwarfLookups << ", hits=" << dwarfHits << "\n"
            << "ELF image cache: lookups: " << elfLookups << ", hits=" << elfHits << std::endl;
        *debug << "executable images by name:\n";

        auto dumpcache = [&] (const auto &map, const char *descr) {
            *debug << descr << "\n";
            for (const auto &[name, elf] : map) {
                *debug << "\t" << name << ": " << *elf->io << std::endl;
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

template <typename Container>
std::shared_ptr<Elf::Object>
Context::getImageIfLoaded( const Container &ctr, const typename Container::key_type &key) {
    elfLookups++;
    auto it = ctr.find(key);
    if (it != ctr.end()) {
        elfHits++;
        if (verbose) {
            *debug << "cache hit for ELF image " << key << "\n";
        }
        return it->second;
    }
    return {};
}

std::shared_ptr<Elf::Object>
Context::getImage(const std::string &name, bool isDebug) {
    auto &map = isDebug ? debugImageByName : imageByName;
    auto res = getImageIfLoaded(map, name);
    if (res != nullptr)
        return res;
    auto elf = std::make_shared<Elf::Object>(*this, std::make_shared<MmapReader>(*this, name), isDebug);
    // don't cache negative entries: assign into the cache after we've constructed:
    // a failure to load the image will throw.
    if (verbose)
        *debug << "loaded image from file " << name << "\n";
    map[name] = elf;
    auto bid = elf->getBuildID();
    if (bid) {
        if (isDebug)
            debugImageByID[bid] = elf;
        else
            imageByID[bid] = elf;
    }
    return elf;
}


std::shared_ptr<Elf::Object>
Context::getDebugImage(const std::string &name) {
    // the name here generally comes from the .debug_link field, so is a
    // relative path. Search the debug dirs for a debug image
    for (const auto &dir : debugDirectories) {
        auto img = getImageIfLoaded(debugImageByName, stringify(dir, "/", name));
        if (img)
            return img;
    }
    for (const auto &dir : debugDirectories) {
        try {
            return getImage(stringify(dir, "/", name), true);
        }
        catch (const std::exception &ex) {
            continue;
        }
    }
    if (verbose)
        *debug << "no debug image found for name " << name << "\n";
    return {};
}


std::string buildIdPath(const Elf::BuildID &bid) {
    std::ostringstream dir;
    dir << ".build-id/" << std::hex << std::setw(2) << std::setfill('0') << int(bid.data[0]);
    for (size_t i = 1; i < bid.data.size(); ++i)
        dir << std::hex << std::setw(2) << std::setfill('0') << int(bid.data[i]);
    return dir.str();
}

namespace Elf {
std::ostream &
operator << (std::ostream &os, const Elf::BuildID &bid) {
    os << std::hex << std::setw(2) << std::setfill('0') << int(bid.data[0]);
    for (size_t i = 1; i < bid.data.size(); ++i)
        os << std::hex << std::setw(2) << std::setfill('0') << int(bid.data[i]);
    return os;
}
}


std::shared_ptr<Elf::Object>
Context::getDebugImage(const Elf::BuildID &bid) {
    // First, try the local filesystem, converting the buildid to a search path.
    if (auto img = debugImageByID.find(bid); img != debugImageByID.end())
        return img->second;
    auto debugObject = getDebugImage(buildIdPath(bid));
#ifdef DEBUGINFOD
    if (!debugObject && debuginfod) {
        char *path;
        int fd = debuginfod_find_debuginfo(debuginfod.get(), bid.data.data(), int( bid.data.size() ), &path);
        if (fd >= 0) {
            // Wrap the fd in a reader, and then a cache reader...
            std::shared_ptr<Reader> reader = std::make_shared<FileReader>(*this, path, fd );
            reader = std::make_shared<CacheReader>(reader);
            // and then wrap the lot in an ELF object.
            debugObject = std::make_shared<Elf::Object>( *this, reader, true );
            free(path);
            debugImageByID[bid] = debugObject;
            if (verbose) {
                *debug << "loaded debuginfo for " << bid << " from debuginfod\n";
            }
            return debugObject;
        }
        if (verbose)
            *debug << "failed to fetch debuginfo for " << bid << " with debuginfod: " << strerror(-fd) << "\n";
    }
#endif
    if (verbose)
        *debug << "no debug image found for build-id " << bid << "\n";
    return {};
}

std::shared_ptr<Elf::Object>
Context::getImage(const Elf::BuildID &bid) {
    // return it if we already have it.
    if ( auto img = imageByID.find(bid); img != imageByID.end())
        return img->second;

    // get it from the filesystem first.
    auto path = std::string("/usr/lib/" ) + buildIdPath( bid );
    try {
        if (auto debugImage = getImage(path); debugImage)
            return debugImage;
    }
    catch (...) {
    }

#ifdef DEBUGINFOD
    // use debuginfo?
    if (debuginfod) {
        char *path;
        int fd = debuginfod_find_executable(debuginfod.get(), bid.data.data(), int( bid.data.size() ), &path);
        if (fd >= 0) {
            // Wrap the fd in a reader, and then a cache reader...
            std::shared_ptr<Reader> reader = std::make_shared<FileReader>(*this, path, fd );
            reader = std::make_shared<CacheReader>(reader);
            // and then wrap the lot in an ELF object.
            auto exeImage = std::make_shared<Elf::Object>( *this, reader, true );
            free(path);
            imageByID[bid] = exeImage;
            if (verbose)
                *debug << "fetched executable for " << bid << " with debuginfod: " << strerror(-fd) << "\n";
            return exeImage;
        } else if (verbose) {
            *debug << "failed to fetch executable for " << bid << " with debuginfod: " << strerror(-fd) << "\n";
        }
    }
#endif
    return {};
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
