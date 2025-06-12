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
    return getDwarf(getImageForName(filename));
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
        for (const auto &[name, elf] : elfCache) {
            *debug << "\t" << *elf->io << std::endl;
        }
    }
}

void
Context::flush(std::shared_ptr<Elf::Object> o)
{
    for (auto it = elfCache.begin(); it != elfCache.end(); ++it) {
        if (it->second == o) {
            elfCache.erase(it);
            break;
        }
    }
    dwarfCache.erase(o);
}

std::shared_ptr<Elf::Object>
Context::getImageForName(const std::string &name, bool isDebug) {
    if (options.noLocalFiles)
        return nullptr;
    auto res = getImageIfLoaded(name);
    if (res != nullptr)
        return res;
    auto item = std::make_shared<Elf::Object>(*this, std::make_shared<MmapReader>(*this, name), isDebug);
    // don't cache negative entries: assign into the cache after we've constructed:
    // a failure to load the image will throw.
    elfCache[name] = item;
    return item;
}

std::shared_ptr<Elf::Object>
Context::getImageIfLoaded(const std::string &name)
{
    elfLookups++;
    auto it = elfCache.find(name);
    if (it != elfCache.end()) {
        elfHits++;
        return it->second;
    }
    return {};
}

std::shared_ptr<Elf::Object>
Context::getDebugImage(const std::string &name) {
    // XXX: verify checksum.
    for (const auto &dir : debugDirectories) {
        auto img = getImageIfLoaded(stringify(dir, "/", name));
        if (img)
            return img;
    }
    for (const auto &dir : debugDirectories) {
        try {
           return getImageForName(stringify(dir, "/", name), true);
        }
        catch (const std::exception &ex) {
            continue;
        }
    }
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
