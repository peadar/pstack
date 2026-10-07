#ifndef LIBPSTACK_GO_H
#define LIBPSTACK_GO_H

#include "libpstack/dwarf.h"

#include <optional>
#include <string>
#include <string_view>

namespace pstack::Go {

struct RuntimeOffsets {
    std::string version;
    std::string machine;
    size_t pointerSize{};
    uintmax_t allgsData{};
    uintmax_t allgsLength{};
    uintmax_t allgsStride{};
    uintmax_t gSize{};
    uintmax_t gSched{};
    uintmax_t gGoid{};
    uintmax_t gobufSp{};
    uintmax_t gobufPc{};
    std::optional<uintmax_t> gobufBp;
    std::optional<uintmax_t> gobufG;
    std::optional<uintmax_t> gobufCtxt;
    std::optional<uintmax_t> gobufLr;
    void parse(std::istream &);
};

std::string offsetFileName(std::string_view version, std::string_view machineName);
std::string versionSeries(std::string_view version);
std::string version(const Elf::Object &);
const RuntimeOffsets &getOffsets(Context &, const Elf::Object &);
RuntimeOffsets runtimeOffsets(const Dwarf::Info::sptr &, std::string version,
        std::string machine, size_t pointerSize);

} // namespace pstack::Go

#endif
