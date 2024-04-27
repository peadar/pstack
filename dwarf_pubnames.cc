#include "libpstack/dwarf.h"
#include "libpstack/dwarf_reader.h"

namespace pstack::Dwarf {

Pubname::Pubname(DWARFReader &r, uint32_t offset)
    : offset(offset)
    , name(r.getstring())
{
}

PubnameUnit::PubnameUnit(DWARFReader &r)
{
    length = r.getu32();
    Elf::Off next = r.getOffset() + length;

    version = r.getu16();
    infoOffset = r.getu32();
    infoLength = r.getu32();

    while (r.getOffset() < next) {
        uint32_t offset = r.getu32();
        if (offset == 0)
            break;
        pubnames.emplace_back(r, offset);
    }
}

}
