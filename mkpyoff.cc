#include "libpstack/context.h"
#include "libpstack/elf.h"
#include "libpstack/dwarf.h"
#include <cassert>
#include <iostream>

namespace pstack { namespace {

[[noreturn]] void usage() {
    std::cerr << "usage: mkpyoff <lib>\n";
    exit(1);
}

Dwarf::DIE findDIE(pstack::Dwarf::DIE &die, std::string_view name) {
    if (die.name() == name) {
        return die;
    }
    for (auto child : die.children()) {
        return findDIE(child, name);
    }
    return {};
}


Dwarf::DIE findDIE(const pstack::Dwarf::Unit::sptr &unit, std::string_view name) {
    return findDIE(unit->root(), name);
}

Dwarf::DIE findDIE(const pstack::Dwarf::Info::sptr &info, std::string_view name) {
    for (auto unit : info->getUnits()) {
        DIE rv = findDIE(unit, name);
        if (rv)
            return rv;
    }
    return Dwarf::DIE();
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
    return 0;
}


} }

int main(int argc, char *argv[]) {
    pstack::main(argc, argv);
}

