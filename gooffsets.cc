#include "libpstack/go.h"
#include "libpstack/context.h"
#include "libpstack/dwarf.h"

#include <algorithm>
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

    Reader::csptr reader { section.io() };

    Dwarf::DWARFReader dw{reader};

    std::vector<char> vec(14);
    dw.getBytes(vec.size(), (unsigned char *)vec.data());
    if (buildInfoMagic != std::string_view{ vec.data(), vec.size()})
        throw (Exception() << "invalid magic header in .go.buildinfo");
    /* uint8_t pointerSize = */ dw.getu8();
    uint8_t flags = dw.getu8();
    uint64_t versPtr = dw.getObj<uint64_t>();
    /* uint64_t modPtr = */ dw.getObj<uint64_t>();

    if (flags & 0x2) { // Go 1.18 and later: uleb128-length delimited string next.
        auto versionSize = dw.getuleb128();
        vec.resize(versionSize);
        dw.getBytes(versionSize, (unsigned char *)vec.data());
        return std::string(vec.data(), vec.size());
    }
    // go < 1.18: versPtr points to the version string
    auto velf = elf.virtualView();
    uintptr_t ptr = velf->readObj<uintptr_t>(versPtr);
    return velf->readString(ptr);
}

RuntimeOffsets
runtimeOffsets(const Dwarf::Info::sptr &dwarf, std::string goVersion,
        std::string machine, size_t pointerSize)
{
    DIE g;
    std::unordered_set<std::string_view> gname{"runtime.g"};
    findTypes(dwarf, gname, [&](std::string_view, const DIE &die) { g = die; });
    if (!g)
        throw Exception() << ("cannot find runtime.g");

    auto gSize = uintmax_t(g.attribute(Dwarf::DW_AT_byte_size));
    auto schedOffset = memberOffset(g, "sched");
    auto goidOffset = memberOffset(g, "goid");
    if (!gSize || !schedOffset || !goidOffset)
        throw (Exception() << "missing offsets in go's runtime.h");

    DIE gobuf;
    for (const DIE &member : g.children()) {
        if (member.tag() == Dwarf::DW_TAG_member && member.name() == "sched") {
            gobuf = Dwarf::removeTypeQualifiers(DIE(member.attribute(Dwarf::DW_AT_type)));
            break;
        }
    }
    if (!gobuf)
        throw (Exception() << "no go scheduler type info");

    auto sp = memberOffset(gobuf, "sp");
    auto pc = memberOffset(gobuf, "pc");
    auto bp = memberOffset(gobuf, "bp");
    auto gOffset = memberOffset(gobuf, "g");
    auto ctxt = memberOffset(gobuf, "ctxt");
    auto lr = memberOffset(gobuf, "lr");
    if (!sp || !pc)
        throw Exception() << "no stack pointer found in scheduler state";

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
