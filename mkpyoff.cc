#include "libpstack/context.h"
#include "libpstack/elf.h"
#include "libpstack/dwarf.h"
#include <cassert>
#include <iostream>
#include <utility>

namespace pstack { namespace {

[[noreturn]] void usage() {
    std::cerr << "usage: mkpyoff <lib>\n";
    exit(1);
}

struct Pad {
    size_t cnt;
    static std::array<char, 4096> spaces;
};

std::array<char, 4096> Pad::spaces = []() {
        std::array<char, 4096 > spaces_;
        spaces_.fill(' ');
        return spaces_;
}();

std::ostream & operator << (std::ostream &os, const Pad &pad) {
    return os << std::string_view{ Pad::spaces.end() - std::min(pad.cnt * 4, Pad::spaces.size()), Pad::spaces.end() };
}

struct BinDump {
    const Reader::csptr &io;
    off_t offset;
    const Dwarf::DIE &type;
    size_t depth{};
    BinDump(const Reader::csptr &io_, off_t offset_, const Dwarf::DIE &type_, size_t depth_ = 0)
        : io{io_} , offset{offset_} , type{type_}, depth{depth_} { }
    void dump(std::ostream &os) const;
    void dumpBase(std::ostream &os) const;
    void dumpStructFields(std::ostream &os) const;
};

Dwarf::DIE findDIE(const pstack::Dwarf::DIE &die, std::string_view name) {
    if (die.name() == name)
        return die;
    for (auto child : die.children()) {
        auto found = findDIE(child, name);
        if (found)
            return found;
    }
    return {};
}

Dwarf::DIE findDIE(const pstack::Dwarf::Unit::sptr &unit, std::string_view name) {
    return findDIE(unit->root(), name);
}

Dwarf::DIE findDIE(const pstack::Dwarf::Info::sptr &info, std::string_view name) {
    for (auto unit : info->getUnits()) {
        Dwarf::DIE rv = findDIE(unit, name);
        if (rv)
            return rv;
    }
    return Dwarf::DIE();
}


std::ostream &operator << (std::ostream &os, const BinDump &bd) {
    bd.dump(os);
    return os;
}


void BinDump::dumpBase(std::ostream &os) const {
    auto encoding = Dwarf::Encoding(uintptr_t(type.attribute(Dwarf::DW_AT_encoding)));
    switch (encoding) {
        case Dwarf::DW_ATE_unsigned:
            switch (uintptr_t(type.attribute(Dwarf::DW_AT_byte_size))) {
                case 4:
                    os << io->readObj<uint32_t>(offset);
                    break;
                case 8:
                    os << io->readObj<uint64_t>(offset);
                    break;
                case 2:
                    os << io->readObj<uint16_t>(offset);
                default:
                    abort();
            }
            break;
        default:
            abort();
    }
}

void
BinDump::dump(std::ostream &os) const {
    switch (type.tag()) {
        case Dwarf::DW_TAG_structure_type:
            dumpStructFields(os);
            break;
        case Dwarf::DW_TAG_typedef:
            os << BinDump(io, offset, Dwarf::DIE(type.attribute(Dwarf::DW_AT_type)), depth);
            break;

        case Dwarf::DW_TAG_base_type: {
            dumpBase(os);
            break;

        }

        default:
            os << Pad{depth} << type.tag() << "/" << type.name() << "@" << offset;
            break;
    }
}

void
BinDump::dumpStructFields(std::ostream &os) const {
    for (auto &member : type.children()) {
        if (member.tag() != Dwarf::DW_TAG_member)
            continue;
        os << Pad{depth} << member.name() << ": ";
        auto chtype = Dwarf::DIE(member.attribute(Dwarf::DW_AT_type));
        auto fieldOff = member.attribute(Dwarf::DW_AT_data_member_location);
        assert(fieldOff.valid());
        os << BinDump(io, offset + uintptr_t(fieldOff), chtype, depth + 1) << "\n";
    }
    // assert(end == offset);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
      usage();
    }
    pstack::Context ctx;
    auto elf = ctx.findImage(argv[1]);
    if (!elf) {
        std::cerr << "does not look like an ELF image\n";
        usage();
    }

    auto &pyRuntimeSec = elf->getSection(".PyRuntime", SHT_PROGBITS);

    if (!pyRuntimeSec) {
        std::cerr << "does not look like a python interpreter\n";
        usage();
    }

    auto dwarf = ctx.findDwarf(elf);

    auto runtimeType = findDIE(dwarf, "_Py_DebugOffsets");
    if (!runtimeType) {
        dwarf = dwarf->getAltDwarf();
        if (dwarf)
            runtimeType = findDIE(dwarf, "_Py_DebugOffsets");
    }
    assert(runtimeType);
    std::cout << BinDump(pyRuntimeSec.io(), 0, runtimeType, 0);

    std::cout << json(runtimeType);
    return 0;
}


} }

int main(int argc, char *argv[]) {
    pstack::main(argc, argv);
}

