#include "libpstack/python.h"
#include <dlfcn.h>
#include <string.h>
#include <string>
#include <regex.h>
#include "libpstack/proc.h"
#include "libpstack/stringify.h"

namespace pstack {
static std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Addr> getInterpHead(Procman::Process &);
PyInterpInfo
getPyInterpInfo(Procman::Process &proc) {
    Elf::Object::sptr libpython;
    Elf::Addr libpythonAddr;
    Elf::Addr interpreterHead;

    std::tie(libpython, libpythonAddr, interpreterHead) = getInterpHead(proc);

    if (libpython == nullptr)
        return PyInterpInfo {nullptr, 0, 0, "", 0};

    auto [major, minor] = getPythonVersionFromFilename(libpython->io->filename());

    if (proc.context.verbose > 0)
        *proc.context.debug << "python version is: " << major << "." << minor << std::endl;

    return PyInterpInfo {
        libpython, libpythonAddr, interpreterHead,
        "v" + std::to_string(major) + "." + std::to_string(minor),
        V2HEX(major, minor)};
}

std::pair<int, int>
getPythonVersionFromFilename(const std::string &filename) {
    auto lastSlash = filename.rfind('/');
    auto index = filename.find("python", lastSlash == std::string::npos ? 0 : lastSlash);

    if (index == std::string::npos)
        throw Exception() << "Could not find 'python' in filename: " << filename;

    if (filename.length() < index + 9) //index + len("pythonX.Y")
        throw Exception() << "Can't parse python version from lib/exec name: "
            << filename << " (too short)";

    char majorChar = filename[index + 6];
    char minorChar = filename[index + 8];

    if (!isdigit(majorChar) || !isdigit(minorChar))
        throw Exception()
            << "lib/exec name " << filename
            << " doesn't match \"*pythonX.Y.*\" format. Found '"
            << majorChar << "' and '" << minorChar << "' where digits were expected.";

    int major = majorChar - '0';
    int minor = minorChar - '0';
    return {major, minor};
}

std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Addr>
getInterpHead(Procman::Process &proc) {
    // As a local python2 hack, we have a global variable pointing at interp_head
    // We can use that to avoid needing any debug info for the interpreter.
    // (Python3 does not require this hack, because _PyRuntime is exported
    // in the dynamic symbols.)
    try {
        auto [ libpython,  libpythonAddr, interpreterHead ] =
           proc.resolveSymbolDetail("Py_interp_headp", false,
                [&](std::string_view name) {
                    return name.find("python") != std::string::npos;
                });
        if (proc.context.verbose)
            *proc.context.debug << "found interp_headp in ELF syms" << std::endl;
        Elf::Addr interpHead;
        proc.io->readObj(libpythonAddr + interpreterHead.st_value, &interpHead);
        return std::make_tuple(libpython, libpythonAddr, interpHead);
    }
    catch (...) {
        if (proc.context.verbose)
            *proc.context.debug << "Py_interp_headp symbol not found. Trying fallback" << std::endl;
    }

#ifdef WITH_PYTHON2
    try {
        return getInterpHead<2>(proc);
    } catch (...) {
        if (proc.context.verbose)
            *proc.context.debug << "Python 2 interpreter not found" << std::endl;
    }
#endif
#ifdef WITH_PYTHON3
    try {
        return getInterpHead<3>(proc);
    } catch (...) {
        if (proc.context.verbose)
            *proc.context.debug << "Python 3 interpreter not found" << std::endl;
    }
#endif

    if (proc.context.verbose)
        *proc.context.debug << "Couldn't find a python interpreter" << std::endl;

    return std::make_tuple(nullptr, 0, 0);
}

// libpthread includes offsets for fields in various structures. We can use
// _thred_db_pthread_tid to work out the offset within a pthread structure of
// the "tid" in a pthread. This gives us a way to find an LWP for a given
// pthread_t. (In Linux's 1:1 modern threadding model, each pthread_t is associated
// with a single LWP, or Linux task.)
bool
pthreadTidOffset(Procman::Process &proc, size_t *offsetp)
{
    static size_t offset;
    static enum { notDone, notFound, found } status;
    if (status == notDone) {
        try {
            auto addr = proc.resolveSymbol("_thread_db_pthread_tid", true,
                  [](std::string_view name) {
                     return
                     name.find("libc." ) != std::string::npos ||
                     name.find("libpthread" ) != std::string::npos ||
                     name.find("libthread" ) != std::string::npos; });
            uint32_t desc[3];
            proc.io->readObj(addr, &desc[0], 3);
            offset = desc[2];
            status = found;
            if (proc.context.verbose)
                *proc.context.debug << "found thread offset " << offset <<  "\n";
        } catch (const std::exception &ex) {
           if (proc.context.verbose)
               *proc.context.debug << "failed to find offset of tid in pthread: " << ex.what();
            status = notFound;
        }
    }
    if (status == found) {
        *offsetp = offset;
        return true;
    }
    return false;
}
}
