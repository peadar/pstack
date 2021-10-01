// vim: expandtab:ts=4:sw=4

#include "libpstack/dwarf.h"

namespace Dwarf {
Info::sptr
ImageCache::getDwarf(const std::string &filename)
{
    return getDwarf(getImageForName(filename));
}

Info::sptr
ImageCache::getDwarf(Elf::Object::sptr object)
{
    auto it = dwarfCache.find(object);
    dwarfLookups++;
    if (it != dwarfCache.end()) {
        dwarfHits++;
        return it->second;
    }
    auto dwarf = std::make_shared<Info>(object, *this);
    dwarfCache[object] = dwarf;
    return dwarf;
}

ImageCache::ImageCache() : dwarfHits(0), dwarfLookups(0) { }

ImageCache::~ImageCache() {
    if (verbose >= 2)
        *debug << "DWARF image cache: lookups: " << dwarfLookups << ", hits="
            << dwarfHits << std::endl;
}

void
ImageCache::flush(Elf::Object::sptr o)
{
    Elf::ImageCache::flush(o);
    dwarfCache.erase(o);
}

}
