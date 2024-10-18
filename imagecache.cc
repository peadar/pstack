// vim: expandtab:ts=4:sw=4

#include "libpstack/imagecache.h"
#include "libpstack/dwarf.h"
#include "libpstack/stringify.h"
#include "libpstack/global.h"

namespace pstack {
int dwarfLookups, elfLookups, dwarfHits, elfHits;
bool noExtDebug;
std::vector<std::string> globalDebugDirectories = {
    "/usr/lib/debug", 
    "/usr/lib/debug/usr"
};

std::shared_ptr<Dwarf::Info>
ImageCache::getDwarf(const std::string &filename)
{
    return getDwarf(getImageForName(filename));
}

Dwarf::Info::sptr
ImageCache::getDwarf(Elf::Object::sptr object)
{
    auto it = dwarfCache.find(object);
    dwarfLookups++;
    if (it != dwarfCache.end()) {
        dwarfHits++;
        return it->second;
    }
    auto dwarf = std::make_shared<Dwarf::Info>(object, *this);
    dwarfCache[object] = dwarf;
    return dwarf;
}

ImageCache::~ImageCache() noexcept {
    if (verbose >= 2) {
        *debug << "image cache: lookups: " << dwarfLookups << ", hits=" << dwarfHits << "\n"
               << "ELF image cache: lookups: " << elfLookups << ", hits=" << elfHits << std::endl;
        for (const auto &[name, elf] : cache) {
            *debug << "\t" << *elf->io << std::endl;
        }
    }
}

void
ImageCache::flush(std::shared_ptr<Elf::Object> o)
{
    for (auto it = cache.begin(); it != cache.end(); ++it) {
        if (it->second == o) {
            cache.erase(it);
            break;
        }
    }
    dwarfCache.erase(o);
}

std::shared_ptr<Elf::Object>
ImageCache::getImageForName(const std::string &name, bool isDebug) {
    auto res = getImageIfLoaded(name);
    if (res != nullptr)
        return res;
    auto item = std::make_shared<Elf::Object>(*this, std::make_shared<MmapReader>(name), isDebug);
    // don't cache negative entries: assign into the cache after we've constructed:
    // a failure to load the image will throw.
    cache[name] = item;
    return item;
}

std::shared_ptr<Elf::Object>
ImageCache::getImageIfLoaded(const std::string &name)
{
    elfLookups++;
    auto it = cache.find(name);
    if (it != cache.end()) {
        elfHits++;
        return it->second;
    }
    return {};
}

std::shared_ptr<Elf::Object>
ImageCache::getDebugImage(const std::string &name) {
    // XXX: verify checksum.
    for (const auto &dir : globalDebugDirectories) {
        auto img = getImageIfLoaded(stringify(dir, "/", name));
        if (img)
            return img;
    }
    for (const auto &dir : globalDebugDirectories) {
        try {
           return getImageForName(stringify(dir, "/", name), true);
        }
        catch (const std::exception &ex) {
            continue;
        }
    }
    return {};
}


}
