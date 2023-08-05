#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"
#include "libpstack/stringify.h"
#include "libpstack/global.h"
#include "libpstack/fs.h"

#include <sys/ptrace.h>
#include <sys/types.h>

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <wait.h>

#include <climits>
#include <iostream>
#include <utility>
#include <fstream>
#include <ucontext.h>
#include <dlfcn.h>

SelfProcess::SelfProcess(const Elf::Object::sptr &ex, const PstackOptions &options, Dwarf::ImageCache &imageCache)
    : Process( ex ? ex : imageCache.getImageForName("/proc/self/exe"),
            std::make_shared<MemReader>("me", std::numeric_limits<size_t>::max(), reinterpret_cast<void *>(0)), // the entire of our own address space.
            options, imageCache)
{
}

Reader::csptr
SelfProcess::getAUXV() const
{
    return loadFile("/proc/self/auxv");
}

bool
SelfProcess::getRegs(lwpid_t pid, Elf::CoreRegisters *reg)
{
    ucontext_t context;
    assert(pid == getpid());
    getcontext(&context);

#ifdef __aarch64__
    assert(sizeof reg->regs == sizeof context.uc_mcontext.regs);
    memcpy(reg->regs, &context.uc_mcontext.regs, sizeof  reg->regs);
#else
    gregset2core(*reg, context.uc_mcontext.gregs);
#endif
    return true;
}

void
SelfProcess::resume(lwpid_t)
{
}

pid_t
SelfProcess::getPID() const
{
    return pid;
}

void
SelfProcess::stopProcess()
{
}

void
SelfProcess::resumeProcess()
{
}

void
SelfProcess::stop(lwpid_t)
{
}

std::vector<AddressRange>
SelfProcess::addressSpace() const {
    std::vector<AddressRange> rv;
    std::ifstream input("/proc/self/maps");
    for (;;) {
       std::string startS, endS, restS;
       getline(input, startS, '-');
       getline(input, endS, ' ');
       getline(input, restS);
       if (input.eof() || !input.good())
          break;

       size_t pos;
       Elf::Addr start = stoull(startS, &pos, 16);
       if (startS[pos] != 0)
          continue;
       Elf::Addr end = stoull(endS, &pos, 16);
       if (endS[pos] != 0)
          continue;
       rv.emplace_back(start, end - start, end - start);
    }
    return rv;
}

bool
SelfProcess::loadSharedObjectsFromFileNote()
{
    // In theory we can implement this by grovelling in /proc/<pid>/maps, but
    // it mostly exists for truncated core files, so don't bother now.
    return false;
}

Elf::Addr
SelfProcess::findRDebugAddr() {
    return Elf::Addr(dlsym(RTLD_DEFAULT, "_r_debug"));
}

