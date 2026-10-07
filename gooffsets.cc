#include "libpstack/go.h"
#include "libpstack/context.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <functional>

namespace pstack::Go {
namespace {

using Dwarf::DIE;
constexpr std::string_view buildInfoMagic { "\xff Go buildinf:" };

std::optional<uintmax_t>
memberOffset(const DIE &type, std::string_view name)
{
    if (!type)
        return std::nullopt;
    for (const DIE &member : type.children()) {
        if (member.tag() != Dwarf::DW_TAG_member || member.name() != name)
            continue;
        auto offset = member.attribute(Dwarf::DW_AT_data_member_location);
        if (offset.valid())
            return uintmax_t(offset);
    }
    return std::nullopt;
}

DIE
realType(DIE type, unsigned depth = 0)
{
    if (!type || depth > 16)
        return {};
    switch (type.tag()) {
        case Dwarf::DW_TAG_typedef:
        case Dwarf::DW_TAG_const_type:
        case Dwarf::DW_TAG_volatile_type:
        case Dwarf::DW_TAG_restrict_type:
        case Dwarf::DW_TAG_atomic_type:
        case Dwarf::DW_TAG_pointer_type:
            return realType(DIE(type.attribute(Dwarf::DW_AT_type)), depth + 1);
        default:
            return type;
    }
}

void
findType(const DIE &die, std::string_view name, DIE &result)
{
    if (!die || result)
        return;
    if (die.name() == name) {
        auto type = realType(die);
        if (type && type.hasChildren()) {
            result = std::move(type);
            return;
        }
    }
    for (const DIE &child : die.children()) {
        findType(child, name, result);
        if (result)
            return;
    }
}

DIE
findType(const Dwarf::Info::sptr &dwarf, std::string_view name)
{
    DIE result;
    for (const auto &unit : dwarf->getUnits()) {
        findType(unit->root(), name, result);
        if (result)
            break;
    }
    return result;
}

uint64_t
readUint(std::span<const char> bytes, size_t offset, size_t width, bool littleEndian)
{
    if ((width != 4 && width != 8) || offset > bytes.size() || width > bytes.size() - offset)
        throw Exception() << "invalid Go build info integer";
    uint64_t result = 0;
    for (size_t i = 0; i < width; ++i) {
        const size_t shift = littleEndian ? i : width - i - 1;
        result |= uint64_t(static_cast<unsigned char>(bytes[offset + i])) << (shift * 8);
    }
    return result;
}

std::pair<uint64_t, size_t>
readUvarint(std::span<const char> bytes, size_t offset)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 10 && offset + i < bytes.size(); ++i) {
        unsigned char b = bytes[offset + i];
        if (i == 9 && b > 1)
            break;
        value |= uint64_t(b & 0x7f) << (7 * i);
        if (!(b & 0x80))
            return { value, i + 1 };
    }
    throw Exception() << "invalid Go build info string length";
}

std::string
readOldBuildInfoString(const Reader::csptr elf, uint64_t headerAddress, size_t pointerSize,
        bool littleEndian)
{
    std::array<char, 16> header{};
    elf->read(headerAddress, 2 * pointerSize, header.data());
    auto fields = std::span<const char>(header.data(), 2 * pointerSize);
    auto stringAddress = readUint(fields, 0, pointerSize, littleEndian);
    auto stringLength = readUint(fields, pointerSize, pointerSize, littleEndian);
    if (stringLength > 256)
        throw Exception() << "implausible Go version string length";
    std::string value(stringLength, '\0');
    elf->read(stringAddress, value.size(), value.data());
    return value;
}

}

void
RuntimeOffsets::parse(std::istream &in) {
    RuntimeOffsets offsets;

    // map from key to function to set the content in offsets. The bool is
    // whether this field is mandatory. We remove each field as we parse it, so
    // if there are any mandatory ones left at the end, it's an error.
    std::map<std::string_view, std::pair<bool, std::function<void()>>> m = {
        { "version", {true, [&]() { version = parseString(in); } }},
        { "machine", {true, [&]() { machine = parseString(in); } }},
        { "pointer_size", {true, [&]() { pointerSize = parseInt<size_t>(in); } }},
        { "allgs_data", {true, [&]() { allgsData = parseInt<uintmax_t>(in); } }},
        { "allgs_length", {true, [&]() { allgsLength = parseInt<uintmax_t>(in); } }},
        { "allgs_stride", {true, [&]() { allgsStride = parseInt<uintmax_t>(in); } }},
        { "g_size", {true, [&]() { gSize = parseInt<uintmax_t>(in); } }},
        { "g_sched", {true, [&]() { gSched = parseInt<uintmax_t>(in); } }},
        { "g_goid", {true, [&]() { gGoid = parseInt<uintmax_t>(in); } }},
        { "gobuf_sp", {true, [&]() { gobufSp = parseInt<uintmax_t>(in); } }},
        { "gobuf_pc", {true, [&]() { gobufPc = parseInt<uintmax_t>(in); } }},
        { "gobuf_bp", {false, [&]() { gobufBp = parseInt<uintmax_t>(in); } }},
        { "gobuf_g", {false, [&]() { gobufG = parseInt<uintmax_t>(in); } }},
        { "gobuf_ctxt", {false, [&]() { gobufCtxt = parseInt<uintmax_t>(in); } }},
        { "gobuf_lr", {false, [&]() { gobufLr = parseInt<uintmax_t>(in); } }},
    };

    parseObject(in, [&](std::istream &is, std::string field) {
            auto node = m.extract(field);
            if (node) {
                node.mapped().second();
            } else {
                parseValue(is);
            }});

    if (std::any_of(m.begin(), m.end(), [](const auto value) { return value.second.second; } ) ) {
        throw Exception() << "missing go fields";
    }
}
 // namespace

std::string
versionSeries(std::string_view goVersion)
{
    const auto go = goVersion.find("go");
    if (go == std::string_view::npos || go + 2 >= goVersion.size() ||
            !std::isdigit(static_cast<unsigned char>(goVersion[go + 2])))
        throw Exception() << "cannot determine Go major.minor version from '" << goVersion << "'";
    size_t end = go + 2;
    while (end < goVersion.size() && std::isdigit(static_cast<unsigned char>(goVersion[end])))
        ++end;
    if (end == go + 2 || end >= goVersion.size() || goVersion[end] != '.')
        throw Exception() << "cannot determine Go major.minor version from '" << goVersion << "'";
    ++end;
    const size_t minorStart = end;
    while (end < goVersion.size() && std::isdigit(static_cast<unsigned char>(goVersion[end])))
        ++end;
    if (end == minorStart)
        throw Exception() << "cannot determine Go major.minor version from '" << goVersion << "'";
    return std::string(goVersion.substr(go, end - go));
}

std::string
offsetFileName(std::string_view goVersion, std::string_view machineName)
{
    return "gooff-" + versionSeries(goVersion) + "-" + std::string(machineName) + ".json";
}

namespace {

RuntimeOffsets
loadOffsets(Context &context, const std::string &version, const std::string &machineName)
{
    const auto fileName = offsetFileName(version, machineName);
    for (const auto &directory : findXdgDataDirs()) {
        auto path = directory / fileName;
        std::ifstream in(path);
        if (!in)
            continue;
        RuntimeOffsets offsets;
        offsets.parse(in);
        if (versionSeries(offsets.version) != versionSeries(version) ||
                offsets.machine != machineName)
            throw Exception() << "Go offset data in " << path << " does not match its filename";
        if (offsets.pointerSize != sizeof(Elf::Addr))
            throw Exception() << "Go offset data in " << path << " has the wrong pointer size";
        if (context.verbose)
            *context.debug << "found Go offsets data in " << path << "\n";
        return offsets;
    }
    throw Exception() << "cannot find '" << fileName << "' - run pstack-mkgooff on a Go executable built with this Go version";
}

}

const RuntimeOffsets &
getOffsets(Context &context, const Elf::Object &elf)
{
    static std::map<std::string, RuntimeOffsets> allOffsets;

    const std::string goVersion = version(elf);
    const std::string machineName = elf.getMachineName();
    const std::string key = offsetFileName(goVersion, machineName);

    auto iter = allOffsets.find(key);
    if (iter != allOffsets.end())
        return iter->second;
    auto offsets = loadOffsets(context, goVersion, machineName);
    return allOffsets.emplace(key, std::move(offsets)).first->second;
}

std::string
version(const Elf::Object &elf)
{
    const auto &section = elf.getSection(".go.buildinfo", SHT_PROGBITS);
    if (!section)
        throw Exception() << "Go build info section not found";

    auto reader = section.io();
    if (reader->size() > 1024 * 1024)
        throw Exception() << "Go build info section is implausibly large";
    std::vector<char> data(reader->size());
    reader->read(0, data.size(), data.data());
    auto bytes = std::span<const char>(data);
    auto magic = std::search(data.begin(), data.end(), buildInfoMagic.begin(), buildInfoMagic.end());
    if (magic == data.end())
        throw Exception() << "Go build info magic not found";
    const size_t start = magic - data.begin();
    if (start + 32 > data.size())
        throw Exception() << "truncated Go build info header";

    const unsigned char pointerSize = data[start + 14];
    const unsigned char flags = data[start + 15];
    if (flags & 0x2) { // Go 1.18 and later store both strings inline.
        auto [length, used] = readUvarint(bytes, start + 32);
        const size_t text = start + 32 + used;
        if (length > bytes.size() - text)
            throw Exception() << "truncated Go version in build info";
        return std::string(bytes.data() + text, length);
    }

    if (pointerSize != 4 && pointerSize != 8)
        throw Exception() << "invalid pointer size in Go build info";
    const bool littleEndian = elf.getHeader().e_ident[EI_DATA] == ELFDATA2LSB;
    const uint64_t stringHeader = readUint(bytes, start + 16, pointerSize, littleEndian);
    return readOldBuildInfoString(elf.virtualView(), stringHeader, pointerSize, littleEndian);
}

RuntimeOffsets
runtimeOffsets(const Dwarf::Info::sptr &dwarf, std::string goVersion,
        std::string machine, size_t pointerSize)
{
    DIE g = findType(dwarf, "runtime.g");
    auto gSize = g ? uintmax_t(g.attribute(Dwarf::DW_AT_byte_size)) : 0;
    auto schedOffset = memberOffset(g, "sched");
    auto goidOffset = memberOffset(g, "goid");
    if (!g || !gSize || !schedOffset || !goidOffset)
        throw Exception() << "Go runtime DWARF does not describe runtime.g";

    DIE gobuf;
    for (const DIE &member : g.children()) {
        if (member.tag() == Dwarf::DW_TAG_member && member.name() == "sched") {
            gobuf = realType(DIE(member.attribute(Dwarf::DW_AT_type)));
            break;
        }
    }
    auto sp = memberOffset(gobuf, "sp");
    auto pc = memberOffset(gobuf, "pc");
    auto bp = memberOffset(gobuf, "bp");
    auto gOffset = memberOffset(gobuf, "g");
    auto ctxt = memberOffset(gobuf, "ctxt");
    auto lr = memberOffset(gobuf, "lr");
    auto gobufSize = gobuf ? uintmax_t(gobuf.attribute(Dwarf::DW_AT_byte_size)) : 0;
    if (!sp || !pc || !gobufSize)
        throw Exception() << "Go runtime DWARF does not describe runtime.gobuf";

    RuntimeOffsets offsets {
        .version = std::move(goVersion),
        .machine = std::move(machine),
        .pointerSize = pointerSize,
        .allgsData = 0,
        .allgsLength = pointerSize,
        .allgsStride = pointerSize,
        .gSize = gSize,
        .gSched = *schedOffset,
        .gGoid = *goidOffset,
        .gobufSp = *sp,
        .gobufPc = *pc,
        .gobufBp = bp,
        .gobufG = gOffset,
        .gobufCtxt = ctxt,
        .gobufLr = lr,
    };
    return offsets;
}

} // namespace pstack::Go
