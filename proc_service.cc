#include "libpstack/proc.h"

#include <thread_db.h>
#include <proc_service.h>
#include <cstdarg>

using pstack::Procman::Process;
using namespace pstack;

extern "C" {

ps_err_e
ps_pcontinue(struct ps_prochandle *ph)
{
    auto p = static_cast<Process *>(ph);
    try {
        p->resumeProcess();
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

ps_err_e
ps_lcontinue(struct ps_prochandle *ph, lwpid_t pid)
{
    auto p = static_cast<Process *>(ph);
    try {
        p->resume(pid);
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

ps_err_e ps_pdmodel(struct ps_prochandle * /* unused */, int * /* unused */)
{
    abort();
    return (PS_ERR);
}

ps_err_e
ps_pglobal_lookup(struct ps_prochandle *ph, const char *ld_object_name,
                  const char *ld_symbol_name, psaddr_t *ld_symbol_addr)
{
    auto p = static_cast<Process *>(ph);
    try {
        *ld_symbol_addr = psaddr_t(intptr_t(p->resolveSymbol(ld_symbol_name, true,
            [ld_object_name](std::string_view name) {
                if (ld_object_name == nullptr) {
                  // Null pointer for object name means look at all objects.
                  // Also, avoid constructing a string_view with a nullptr.
                  return true;
                }
                auto bn = std::filesystem::path(name).filename();
                return bn == ld_object_name || bn == "libc.so.6";
            }
            )));
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

void
ps_plog(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

ps_err_e
ps_pread(struct ps_prochandle *ph, psaddr_t addr, void *buf, size_t len)
{
    auto *p = static_cast<const Process *>(ph);
    try {
        p->io->readObj(Elf::Off(addr), (char *)buf, len);
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

ps_err_e
ps_pstop(struct ps_prochandle *ph)
{
    auto *p = static_cast<Process *>(ph);
    try {
        p->stopProcess();
        return PS_OK;
    } catch (...) {
        return PS_ERR;
    }
}

ps_err_e
ps_pwrite(struct ps_prochandle * /* unused */, psaddr_t /* unused */, const void * /* unused */, size_t /* unused */)
{
    return (PS_ERR);
}


pid_t
ps_getpid(struct ps_prochandle *p)
{
    return static_cast<Process *>(p)->getPID();
}

ps_err_e
ps_pdread(struct ps_prochandle *p, psaddr_t addr, void *d, size_t l)
{
    try {
        static_cast<Process *>(p)->io->readObj(Elf::Off(addr), (char *)d, l);
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

ps_err_e
ps_pdwrite(struct ps_prochandle * /* unused */, psaddr_t /* unused */,
      const void * /* unused */, size_t /* unused */)
{
    abort();
    return PS_ERR;
}

ps_err_e
ps_ptread(struct ps_prochandle * /* unused */, psaddr_t /* unused */,
      void * /* unused */, size_t /* unused */)
{
    abort();
    return PS_ERR;
}

ps_err_e
ps_ptwrite(struct ps_prochandle * /* unused */, psaddr_t /* unused */,
      const void * /* unused */, size_t /* unused */)
{
    abort();
    return PS_ERR;
}


#ifdef __i386__
ps_err_e
ps_lgetxmmregs (struct ps_prochandle * /* unused */,
      lwpid_t /* unused */, char * /* unused */)
{
    abort();
    return (PS_ERR);
}
ps_err_e
ps_lsetxmmregs (struct ps_prochandle * /* unused */, lwpid_t /* unused */,
      const char * /* unused */)
{
    abort();
    return (PS_ERR);
}
#endif

ps_err_e ps_lgetfpregs(struct ps_prochandle * /* unused */, lwpid_t /* unused */,
      prfpregset_t * /* unused */)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_lgetregs(struct ps_prochandle *ph, lwpid_t pid, prgregset_t gregset)
{
   auto p = static_cast<Process *>(ph);
   auto gregs = reinterpret_cast<user_regs_struct *>(gregset);
   try {
      p->getRegset<user_regs_struct, NT_PRSTATUS>(pid, *gregs);
      return PS_OK;
   }
   catch (const Exception &ex) {
      return PS_ERR;
   }
}

ps_err_e ps_lsetfpregs(struct ps_prochandle * /* unused */, lwpid_t /* unused */,
      const prfpregset_t * /* unused */)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_lsetregs(struct ps_prochandle * /* unused */, lwpid_t /* unused */,
      const prgregset_t /* unused */)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_lstop(struct ps_prochandle *ph, lwpid_t lwpid)
{
    auto p = static_cast<Process *>(ph);
    try {
        p->stop(lwpid);
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

}
