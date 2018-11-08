#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"

#include <cstdarg>

extern "C" {

ps_err_e
ps_pcontinue(const struct ps_prochandle *ph)
{
    auto p = const_cast<Process *>(static_cast<const Process *>(ph));
    try {
        p->resumeProcess();
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}

ps_err_e
ps_lcontinue(const struct ps_prochandle *ph, lwpid_t pid)
{
    auto p = const_cast<Process *>(static_cast<const Process *>(ph));
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
ps_pglobal_lookup(struct ps_prochandle *ph, const char *ld_object_name, const char *ld_symbol_name, psaddr_t *ld_symbol_addr)
{
    auto p = static_cast<const Process *>(ph);
    try {
        *ld_symbol_addr = psaddr_t(intptr_t(p->findSymbolByName(ld_symbol_name,
            [ld_object_name](const Process::LoadedObject &lo) {
                return basename(stringify(*lo.object->io)) == std::string(ld_object_name);
            })));
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
ps_pstop(const struct ps_prochandle *ph)
{
    auto *p = const_cast<Process *>(static_cast<const Process *>(ph));
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
ps_pdwrite(struct ps_prochandle * /* unused */, psaddr_t /* unused */, const void * /* unused */, size_t /* unused */)
{
    abort();
    return PS_ERR;
}

ps_err_e
ps_ptread(struct ps_prochandle * /* unused */, psaddr_t /* unused */, void * /* unused */, size_t /* unused */)
{
    abort();
    return PS_ERR;
}

ps_err_e
ps_ptwrite(struct ps_prochandle * /* unused */, psaddr_t /* unused */, const void * /* unused */, size_t /* unused */)
{
    abort();
    return PS_ERR;
}


#ifdef __i386__
ps_err_e
ps_lgetxmmregs (struct ps_prochandle * /* unused */, lwpid_t /* unused */, char * /* unused */)
{
    abort();
    return (PS_ERR);
}
ps_err_e
ps_lsetxmmregs (struct ps_prochandle * /* unused */, lwpid_t /* unused */, const char * /* unused */)
{
    abort();
    return (PS_ERR);
}
#endif

ps_err_e ps_lgetfpregs(struct ps_prochandle * /* unused */, lwpid_t /* unused */, prfpregset_t * /* unused */)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_lgetregs(struct ps_prochandle *ph, lwpid_t pid, prgregset_t gregset)
{
    auto p = static_cast<Process *>(ph);
    return p->getRegs(pid, (Elf::CoreRegisters *)gregset) ? PS_OK : PS_ERR;
}

ps_err_e ps_lsetfpregs(struct ps_prochandle * /* unused */, lwpid_t /* unused */, const prfpregset_t * /* unused */)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_lsetregs(struct ps_prochandle * /* unused */, lwpid_t /* unused */, const prgregset_t /* unused */)
{
    abort();
    return (PS_ERR);
}

ps_err_e ps_lstop(const struct ps_prochandle *ph, lwpid_t lwpid)
{
    Process *p = const_cast<Process *>(static_cast<const Process *>(ph));
    try {
        p->stop(lwpid);
        return PS_OK;
    }
    catch (...) {
        return PS_ERR;
    }
}
#if defined(__FreeBSD__)
ps_err_e
ps_linfo(struct ps_prochandle *p, lwpid_t pid, void *info)
{
    if (p->pid == -1) {
        if (ptrace(PT_LWPINFO, pid, info,
            sizeof (struct ptrace_lwpinfo)) == -1)
                return (PS_ERR);
        else
                return (PS_OK);
    } else {
        memset(info, 0, sizeof(struct ptrace_lwpinfo));
        return PS_OK;
    }
}

#endif


}
