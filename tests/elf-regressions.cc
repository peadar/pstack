#include "libpstack/elf.h"

#include <array>
#include <bit>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace {
namespace fs = std::filesystem;
using namespace pstack;

void check(bool condition, const std::string &message) {
    if (!condition)
        throw std::runtime_error(message);
}

template <typename Func>
void expectException(Func func, const std::string &message) {
    try {
        func();
    } catch (const Exception &) {
        return;
    }
    throw std::runtime_error(message);
}

struct TempDirectory {
    fs::path path;
    TempDirectory() {
        auto pattern = (fs::temp_directory_path() / "pstack-elf-XXXXXX").string();
        check(mkdtemp(pattern.data()) != nullptr, "cannot create test directory");
        path = pattern;
    }
    ~TempDirectory() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::vector<char> readFile(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    check(bool(input), "cannot read " + path.string());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void writeFile(const fs::path &path, const std::vector<char> &bytes) {
    std::ofstream output(path, std::ios::binary);
    output.write(bytes.data(), bytes.size());
    check(bool(output), "cannot write " + path.string());
}

void testHash(const fs::path &fixture, const fs::path &withoutSections) {
    Context context;
    auto object = context.openImage(fixture);
    const auto [symbol, index] = object->findDynamicSymbol("elf_test_symbol");
    check(index != 0 && symbol.st_shndx != SHN_UNDEF, "dynamic symbol lookup failed");
    check(object->findDynamicSymbol("pstack_missing_symbol").first.st_shndx == SHN_UNDEF,
          "missing dynamic symbol should be undefined");

    // Runtime symbol lookup must also work after the section table is removed.
    auto bytes = readFile(fixture);
    Elf::Ehdr header;
    std::memcpy(&header, bytes.data(), sizeof header);
    header.e_shoff = 0;
    header.e_shnum = 0;
    header.e_shstrndx = SHN_UNDEF;
    std::memcpy(bytes.data(), &header, sizeof header);
    writeFile(withoutSections, bytes);
    auto sectionless = context.openImage(withoutSections);
    const auto [found, foundIndex] = sectionless->findDynamicSymbol("elf_test_symbol");
    check(foundIndex == index && found.st_value == symbol.st_value && found.st_shndx != SHN_UNDEF,
          "dynamic symbol lookup requires section headers");
}

void testDebugLink(const fs::path &stripped, const fs::path &debug, const fs::path &directory) {
    Context context;
    auto original = context.openImage(stripped);
    auto buildID = original->getBuildID();
    check(bool(buildID), "fixture has no build ID");
    auto debugObject = context.openImage(debug, -1, true);
    check(debugObject->getBuildID() == buildID, "separate debug file build ID differs");
    check(bool(debugObject->getSection(".debug_info", SHT_PROGBITS)), "debug fixture has no DWARF");
    check(!original->getSection(".debug_info", SHT_PROGBITS), "fixture was not stripped");

    std::ostringstream id;
    id << buildID;
    auto link = directory / id.str().substr(0, 2) / id.str().substr(2);
    fs::create_directories(link.parent_path());
    fs::create_symlink(fs::absolute(stripped), link);
    context.exeBuildIdPrefixes = {directory};
    context.debugBuildIdPrefixes.clear();
    context.debugPrefixes = {""};
    auto linked = context.findImage(buildID);
    check(bool(linked), "cannot load fixture through build-ID symlink");
    check(bool(linked->getDebugSection(".debug_info", SHT_PROGBITS)),
          "cannot find debug link beside the build-ID symlink target");
}

void testPartialImage(const fs::path &fixture, const fs::path &partial) {
    Context context;
    auto original = context.openImage(fixture);
    auto buildID = original->getBuildID();
    check(bool(buildID), "fixture has no build ID");
    const auto &dynamic = original->getSegments(PT_DYNAMIC);
    check(dynamic.size() == 1, "fixture must have one dynamic segment");
    auto bytes = readFile(fixture);
    check(dynamic[0].p_offset < bytes.size(), "dynamic segment is outside fixture");
    bytes.resize(dynamic[0].p_offset);
    writeFile(partial, bytes);

    // Use file reads so the absent dynamic segment produces EOF, as with a
    // partial core, rather than reading beyond an mmap of a truncated file.
    auto reader = std::make_shared<FileReader>(context, partial);
    auto object = std::make_shared<Elf::Object>(context, reader);
    check(object->getBuildID() == buildID, "missing dynamic data prevents build-ID recovery");
    expectException([&] { object->findDynamicSymbol("elf_test_symbol"); },
                    "partial fixture unexpectedly contains dynamic data");
}

void testReader(const fs::path &fixture) {
    // Keep bytes beyond p_filesz in the file to detect reads that escape the
    // segment. The segment's BSS extends beyond its file-backed contents.
    Elf::Ehdr header{};
    std::memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELF_BITS == 64 ? ELFCLASS64 : ELFCLASS32;
    header.e_ident[EI_DATA] = std::endian::native == std::endian::little ? ELFDATA2LSB : ELFDATA2MSB;
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_version = EV_CURRENT;
    header.e_type = ET_DYN;
    header.e_ehsize = sizeof header;
    header.e_phoff = sizeof header;
    header.e_phentsize = sizeof(Elf::Phdr);
    header.e_phnum = 1;
    Elf::Phdr segment{};
    segment.p_type = PT_LOAD;
    segment.p_offset = 0x100;
    segment.p_vaddr = 0x1000;
    segment.p_filesz = 0x10;
    segment.p_memsz = 0x30;
    std::vector<char> bytes(0x200, 'A');
    std::memcpy(bytes.data(), &header, sizeof header);
    std::memcpy(bytes.data() + header.e_phoff, &segment, sizeof segment);
    writeFile(fixture, bytes);

    Context context;
    auto object = context.openImage(fixture);
    auto reader = object->virtualView();
    check(reader->view("segment remainder", 0x100e)->size() == 2, "unlimited view escapes segment");
    auto bounded = reader->view("bounded", 0x100e, 8);
    check(bounded->size() == 2, "explicit view escapes segment");
    std::array<char, 8> output{};
    check(bounded->read(0, output.size(), output.data()) == 2, "view read escapes segment");
    check(reader->read(0x100e, output.size(), output.data()) == 2, "direct read escapes segment");
    check(reader->read(0x100f, 1, output.data()) == 1 && output[0] == 'A', "last file-backed byte unreadable");
    check(reader->view("empty", 0x1000, 0)->size() == 0, "zero-length view expands");
    check(reader->read(0x1000, 0, output.data()) == 0, "zero-length read expands");
    check(reader->view("end", 0x1010)->size() == 0, "view at file-backed end is not empty");
    check(reader->read(0x1010, 1, output.data()) == 0, "read at file-backed end is not empty");
    expectException([&] { reader->view("bss", 0x1011); }, "view inside BSS should fail");
    expectException([&] { reader->read(0x1011, 1, output.data()); }, "read inside BSS should fail");
    expectException([&] { reader->view("unmapped", 0x2000); }, "unmapped view should fail");
    expectException([&] { reader->readObj<Elf::Word>(0x100e); }, "object read crossing segment should fail");

    std::weak_ptr<Elf::Object> weak = object;
    object.reset();
    check(!weak.expired(), "virtual reader does not retain its ELF object");
    check(reader->read(0x1000, 1, output.data()) == 1, "retained reader is unusable");
    bounded.reset();
    reader.reset();
    check(weak.expired(), "virtual reader creates an ownership cycle");
}

void testRemovedFile(const fs::path &fixture, const fs::path &removed) {
    fs::copy_file(fixture, removed);
    Context context;
    auto object = context.openImage(removed);
    fs::remove(removed);
    check(!object->io->filename().empty(), "removed mapping has no filename");
    std::ostringstream description;
    object->io->describe(description);
    check(!description.str().empty(), "removed mapping has no description");
    check(object->io->readObj<Elf::Ehdr>(0).e_ident[EI_MAG0] == ELFMAG0,
          "removed mapping is unreadable");
}

void testNoteMoves(const fs::path &fixture) {
    static_assert(std::is_nothrow_move_constructible_v<Elf::NoteDesc>);
    static_assert(std::is_nothrow_move_assignable_v<Elf::NoteDesc>);
    static_assert(std::is_nothrow_move_constructible_v<Elf::Notes::iterator>);
    static_assert(std::is_nothrow_move_assignable_v<Elf::Notes::iterator>);

    Context context;
    auto reader = std::make_shared<FileReader>(context, fixture);
    Elf::Note header{};
    header.n_type = Elf::GNU_BUILD_ID;
    Elf::NoteDesc note(header, reader);
    const auto owners = reader.use_count();
    Elf::NoteDesc moved(std::move(note));
    check(reader.use_count() == owners, "moving a note copied its reader");
    Elf::NoteDesc assigned;
    assigned = std::move(moved);
    check(reader.use_count() == owners, "move-assigning a note copied its reader");
    check(assigned.type() == Elf::GNU_BUILD_ID, "note move lost its type");
    auto copied = assigned;
    check(reader.use_count() == owners + 1 && copied.type() == Elf::GNU_BUILD_ID,
          "copying a note no longer shares its reader");

    auto object = context.openImage(fixture);
    const auto objectOwners = object->io.use_count();
    Elf::Notes::segment_iterator segment(object.get());
    Elf::Notes::iterator iterator(std::move(segment));
    Elf::Notes::iterator movedIterator(std::move(iterator));
    {
        Elf::Notes::iterator assignedIterator;
        assignedIterator = std::move(movedIterator);
        check(!(assignedIterator == object->notes().end()), "moved note iterator is at end");
        check((*assignedIterator).name() == "GNU", "moved note iterator is unreadable");
        auto copy = assignedIterator;
        Elf::Notes::iterator copyAssigned;
        copyAssigned = copy;
        check(copyAssigned == assignedIterator, "copied note iterator changed position");
    }
    check(object->io.use_count() == objectOwners,
          "moved-from note iterators retained the segment reader");
}
}

int main(int argc, char **argv) {
    try {
        check(argc == 5, "expected SysV, GNU, stripped and debug fixture paths");
        TempDirectory directory;
        testHash(argv[1], directory.path / "sysv-sectionless.so");
        testHash(argv[2], directory.path / "gnu-sectionless.so");
        testDebugLink(argv[3], argv[4], directory.path / "build-id");
        testPartialImage(argv[2], directory.path / "partial.so");
        testReader(directory.path / "segments.so");
        testRemovedFile(argv[2], directory.path / "removed.so");
        testNoteMoves(argv[2]);
    } catch (const std::exception &ex) {
        std::cerr << "ELF regression: " << ex.what() << '\n';
        return 1;
    }
    return 0;
}
