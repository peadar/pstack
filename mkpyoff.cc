#include "libpstack/context.h"
#include "libpstack/dwarf.h"
#include <cassert>
#include <iostream>
#include <utility>
#include <fstream>
#include <span>
#include <unordered_set>
#include "libpstack/pyrdb.h"

namespace pstack { namespace {

[[noreturn]] void usage() {
    std::cerr << "usage: mkpyoff <lib>\n";
    exit(1);
}

Dwarf::DIE realtype(Dwarf::DIE die) {
   if (die.tag() == Dwarf::DW_TAG_typedef) {
      return realtype(Dwarf::DIE(die.attribute(Dwarf::DW_AT_type)));
   }
   return die;
}

struct TypeDump {
    size_t offset;
    const Dwarf::DIE type;
    size_t depth{};
    TypeDump(size_t offset_, const Dwarf::DIE &type_, size_t depth_ = 0 )
        : offset{offset_} , type{realtype(type_)}, depth{depth_} { }
    void dump(std::ostream &os) const;
    void dumpBase(std::ostream &os) const;
    void dumpArray(std::ostream &os) const;
    void dumpStructFields(std::ostream &os) const;
    void dumpDimension(std::ostream &os, size_t offset, size_t elements,
                            const Dwarf::DIE &eltType, std::span<size_t> moreDimensions) const;
};

using Types = std::unordered_set<std::string_view>;

Dwarf::DIE findTypes(const pstack::Dwarf::Unit::sptr &unit, Types &types, JObject &jo) {
    for ( const auto &root = unit->root(); auto child : root.children()) {
        if (auto it = types.find(child.name()); it != types.end()) {
            child = realtype(std::move(child));
            if (!bool(child.attribute(Dwarf::DW_AT_declaration))) {
                jo.field(*it, TypeDump(0, child, 0));
                types.erase(it);
            }
        }
    }
    return {};
}

Dwarf::DIE findTypes(const pstack::Dwarf::Info::sptr &info, Types &types, JObject &jo) {
    for (auto units = info->getUnits(); auto unit : units) {
        Dwarf::DIE rv = findTypes(unit, types, jo);
        if (rv)
            return rv;
    }
    return Dwarf::DIE();
}

void
TypeDump::dump(std::ostream &os) const {
   switch (type.tag()) {
      case Dwarf::DW_TAG_pointer_type:
      case Dwarf::DW_TAG_array_type:
      case Dwarf::DW_TAG_base_type: {
         os << json(offset);
         break;
      }
      case Dwarf::DW_TAG_union_type: case Dwarf::DW_TAG_structure_type: {
         JObject jo(os);
         jo.field("<size>", uintptr_t(type.attribute(Dwarf::DW_AT_byte_size)));
         if (offset != 0)
            jo.field("<offset>", offset);
         for (auto &member : type.children()) {
            switch (member.tag()) {
               case Dwarf::DW_TAG_member: {
                  auto chtype = realtype(Dwarf::DIE(member.attribute(Dwarf::DW_AT_type)));
                  auto fieldOff = member.attribute(Dwarf::DW_AT_data_member_location);
                  auto fieldOffset = fieldOff.valid() ? uintptr_t(fieldOff) : 0;
                  jo.field(member.name(), TypeDump(offset + fieldOffset, chtype));
                  break;
               }
               default:
                  break;
            }
         }
         break;
      }
      default:
         os << json(JsonNull{});
         break;
   }
}

// clang can't see this being used.
[[maybe_unused]] std::ostream &operator << (std::ostream &os, const JSON<TypeDump> &bd) {
    bd.object.dump(os);
    return os;
}

void generateOne(Context &ctx, std::filesystem::path path) {
    auto elf = ctx.findImage(path);
    if (!elf) {
        std::cerr << path << " is not an ELF image: " << strerror(errno) << "\n";
        return;
    }

    auto &pyRuntimeSec = elf->getSection(".PyRuntime", SHT_PROGBITS);

    if (!pyRuntimeSec) {
        std::cerr << path << " does not look like a Py_DebugOffsets-enabled python interpreter\n";
        return;
    }

    Types types {
       "PyAsyncMethods",
       "_PyRuntimeState",
       "PyBufferProcs",
       "_PyCFrame",
       "_Py_DebugOffsets",
       "PyDescrObject",
       "PyDictKeyEntry",
       "PyDictKeysObject",
       "PyDictUnicodeEntry",
       "PyDictValues",
       "PyHeapTypeObject",
       "_PyInterpreterFrame",
       "PyInterpreterState",
       "PyMappingMethods",
       "PyMemberDef",
       "PyMemberDescrObject",
       "PyNumberMethods",
       "PyObject",
       "PySequenceMethods",
       "PyThreadState",
       "PyTypeObject",
       "PyVarObject",
       "PyCodeObject",
       "PyUnicodeObject",
       "PyTupleObject",
       "PyLongObject",
       "PyListObject",
       "PyBytesObject",
       "PyDictObject",
    };
    auto [sym, idx] = elf->findDynamicSymbol("Py_Version");
    if (sym.st_shndx == SHN_UNDEF) {
        std::cerr << "no Py_Version in " << path << "\n";
        return;
    }

    unsigned long pyv;
    auto phdr = elf->getSegmentForAddress(sym.st_value);
    if (phdr == nullptr) {
        std::cerr << "no segment for Py_Version in " << path << "\n";
        return;
    }
    auto fileOff = sym.st_value - phdr->p_vaddr + phdr->p_offset;
    elf->io->readObj(fileOff, &pyv);

    Py::Version version(pyv, elf->getHeader().e_machine);

    std::filesystem::path outfileName { version.offsetFileName() };
    std::ofstream out(outfileName);
    if (!out.good()) {
        std::cerr << "failed to open " << outfileName << ": " << strerror(errno) << "\n";
        return;
    }

    JObject jo(out);
    auto dwarf = ctx.findDwarf(elf);
    findTypes(dwarf, types, jo);
    if (!types.empty()) {
        auto altDwarf = dwarf->getAltDwarf();
        if (altDwarf)
            findTypes(altDwarf, types, jo);
    }
    if (!types.empty()) {
        std::clog << outfileName << ": missing types (not necessarily fatal):\n";
        for (auto &t : types) {
            std::clog << "\t" << t << "\n";
        }
    }
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
      usage();
    }
    pstack::Context ctx;
    ctx.options.withDebuginfod = true;

    for (auto i : std::span<char *>(argv + 1, argv + argc)) {
        generateOne(ctx, i);
    }
    return 0;
}

} }

int main(int argc, char *argv[]) {
    pstack::main(argc, argv);
}
