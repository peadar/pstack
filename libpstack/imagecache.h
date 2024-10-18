#pragma once
#include <map>
#include <memory>
#include <vector>

namespace pstack {

namespace Elf {
class Object;
}

namespace Dwarf {
class Info;
}


/*
 * A Dwarf Image Cache is an (Elf) ImageCache, but caches Dwarf::Info for the
 * Objects also. (see elf.h:ImageCache)
 */
class ImageCache {
    std::map<std::shared_ptr<Elf::Object>, std::shared_ptr<Dwarf::Info>> dwarfCache;
    std::map<std::string, std::shared_ptr<Elf::Object>> cache;
public:
    std::shared_ptr<Elf::Object> getImageForName(const std::string &name, bool isDebug = false);
    std::shared_ptr<Elf::Object> getImageIfLoaded(const std::string &name);
    std::shared_ptr<Elf::Object> getDebugImage(const std::string &name);
    std::shared_ptr<Dwarf::Info> getDwarf(const std::string &);
    std::shared_ptr<Dwarf::Info> getDwarf(std::shared_ptr<Elf::Object>);
    void flush(std::shared_ptr<Elf::Object> o);
    ImageCache() = default;
    ImageCache(const ImageCache &) = delete;
    ImageCache(ImageCache &&) = delete;
    ImageCache &operator = (const ImageCache &) = delete;
    ImageCache &operator = (ImageCache &&) = delete;
    ~ImageCache() noexcept;
};

extern std::vector<std::string> globalDebugDirectories;
extern bool noExtDebug; // if set, don't look for exernal ELF info, i.e., usinb debuglink, or buildid.

}
