#include "libpstack/proc.h"

#include <sys/ptrace.h>
#include <sys/types.h>

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <wait.h>
#include <cassert>

#include <ucontext.h>
#include <dlfcn.h>
#include <syscall.h> // gettid is still relatively new - use syscall instead.

namespace pstack::Procman {
SelfProcess::SelfProcess(Context &context_, const Elf::Object::sptr &ex)
    : Process( context_, ex ? ex : context_.getImage("/proc/self/exe"),
          std::make_shared<MemReader>("me", std::numeric_limits<size_t>::max(), nullptr))
    , pid( getpid() )
{
}

Reader::csptr
SelfProcess::getAUXV() const
{
    return context.loadFile("/proc/self/auxv");
}

void
SelfProcess::listLWPs(std::function<void(lwpid_t)> cb) {
   cb(int(syscall(SYS_gettid)));
}

size_t
SelfProcess::getRegs(lwpid_t, int code, size_t size, void *regs) // for now, we just support the current thread.
{
    ucontext_t context;
    assert(pid == getpid());
    getcontext(&context);

    switch (code) {
       case NT_PRSTATUS:
#ifdef __aarch64__
          assert(size == sizeof context.uc_mcontext.regs);
          memcpy(regs, &context.uc_mcontext.regs, size);
#else
          assert(size == sizeof (user_regs_struct));
          gregset2core(*reinterpret_cast<user_regs_struct *>(regs), context.uc_mcontext.gregs);
#endif
          return size;
#ifndef __aarch64__ // TODO
       case NT_FPREGSET:
          memcpy(regs, context.uc_mcontext.fpregs, size);
          return size;
#endif
    }
    return 0;
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
    return procAddressSpace("/proc/self/maps");
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

}
