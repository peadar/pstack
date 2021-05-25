#include "libpstack/python.h"
#include <dlfcn.h>
#include <string.h>
#include <regex.h>

static
std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Addr>
getInterpHead(const Process &);

template <int V>
std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Addr>
getInterpHead(const Process &);

PyInterpInfo
getPyInterpInfo(const Process &proc) {
    Elf::Object::sptr libpython;
    Elf::Addr libpythonAddr;
    Elf::Addr interpreterHead;
    
    std::tie(libpython, libpythonAddr, interpreterHead) = getInterpHead(proc);

    if (libpython == nullptr)
        return PyInterpInfo {nullptr, 0, 0, "", 0};

    std::string filename = libpython->io->filename();

    auto index = filename.find("python");

    if (filename.length() < index + 9) //index + len("pythonX.Y")
        throw Exception() << "Can't parse python version from lib/exec name: " << filename;

    char majorChar = filename[index + 6];
    char minorChar = filename[index + 8];

    if (!isdigit(majorChar) || !isdigit(minorChar))
        throw Exception() << "lib/exec name doesn't match \"*pythonX.Y.*\" format";

    int major = majorChar - '0';
    int minor = minorChar - '0';

    if (verbose)
        std::clog << "python version is: " << major << "." << minor << std::endl;

    return PyInterpInfo {
        libpython, libpythonAddr, interpreterHead, 
        "v" + std::to_string(major) + "." + std::to_string(minor),
        V2HEX(major, minor)};
}

template <>
std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Addr>
getInterpHead<2>(const Process &proc) {
    for (auto &o : proc.objects) {
        std::string module = stringify(*o.second->io);
        if (module.find("python") == std::string::npos)
            continue;
        auto image = o.second;
        auto &syms = image->commonSections->debugSymbols;
        for (auto sym : syms) {
            if (sym.name.substr(0, 11) != "interp_head")
                continue;
            auto libpython = o.second;
            auto libpythonAddr = o.first;
            auto interpHead = libpythonAddr + sym.symbol.st_value;
            if (verbose)
                *debug << "python2 library is " << *libpython->io << std::endl;
            return std::make_tuple(libpython, libpythonAddr, interpHead);
        }
    }

    throw Exception() << "No libpython2 found";
}

template <>
std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Addr>
getInterpHead<3>(const Process &proc) {
    Elf::Object::sptr libpython;
    Elf::Addr libpythonAddr;
    Elf::Addr _PyRuntime;

    std::tie(libpython, libpythonAddr, _PyRuntime) = proc.resolveSymbolDetail("_PyRuntime", false);

    Elf::Addr interpHead = _PyRuntime + sizeof(int) * 2  + sizeof(void *)*2;

    if (libpython == nullptr) {
        if (verbose)
            std::clog << "Python 3 interpreter not found" << std::endl;
        throw Exception() << "No libpython3 found";
    }

    if (verbose)
       *debug << "python3 library is " << *libpython->io << std::endl;

    return std::make_tuple(libpython, libpythonAddr, interpHead);
}

std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Addr>
getInterpHead(const Process &proc) {
    try {
        Elf::Object::sptr libpython;
        Elf::Addr libpythonAddr;
        Elf::Addr interpHeadp = proc.resolveSymbol("Py_interp_headp", false,
                [&](Elf::Addr loadAddr, const Elf::Object::sptr &o) mutable {
                    libpython = o;
                    libpythonAddr = loadAddr;
                    auto name = stringify(*o->io);
                    return name.find("python") != std::string::npos;
                });
        if (verbose)
            *debug << "found interp_headp in ELF syms" << std::endl;
        Elf::Addr interpHead;
        proc.io->readObj(interpHeadp, &interpHead);
        return std::make_tuple(libpython, libpythonAddr, interpHead);
    }
    catch (...) {
        if (verbose)
            std::clog << "Py_interp_headp symbol not found. Trying fallback" << std::endl;
    }

    try {
        return getInterpHead<2>(proc);
    } catch (...) {
        if (verbose)
            std::clog << "Python 2 interpreter not found" << std::endl;
    }

    try {
        return getInterpHead<3>(proc);
    } catch (...) {
        if (verbose)
            std::clog << "Python 3 interpreter not found" << std::endl;
    }

    if (verbose)
        std::clog << "Couldn't find a python interpreter" << std::endl;

    return std::make_tuple(nullptr, 0, 0);
}

// libpthread includes offsets for fields in various structures. We can use
// _thred_db_pthread_tid to work out the offset within a pthread structure of
// the "tid" in a pthread. This gives us a way to find an LWP for a given
// pthread_t. (In Linux's 1:1 modern threadding model, each pthread_t is associated
// with a single LWP, or Linux task.)
bool
pthreadTidOffset(const Process &proc, size_t *offsetp)
{
    static size_t offset;
    static enum { notDone, notFound, found } status;
    if (status == notDone) {
        try {
            auto addr = proc.resolveSymbol("_thread_db_pthread_tid", true);
            uint32_t desc[3];
            proc.io->readObj(addr, &desc[0], 3);
            offset = desc[2];
            status = found;
            if (verbose)
                *debug << "found thread offset " << offset <<  "\n";
        } catch (const std::exception &ex) {
           if (verbose)
               *debug << "failed to find offset of tid in pthread: " << ex.what();
            status = notFound;
        }
    }
    if (status == found) {
        *offsetp = offset;
        return true;
    }
    return false;
}
