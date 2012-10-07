#include "elfinfo.h"
#include <map>
#include <sstream>
#include <functional>

struct ps_prochandle {};

class Process;

struct StackFrame {
    Elf_Addr ip;
    Elf_Addr bp;
    std::vector<Elf_Word> args;
    const char *unwindBy;
    StackFrame(Elf_Addr ip_, Elf_Addr bp_) : ip(ip_), bp(bp_), unwindBy(0) {}
};

struct ThreadStack {
    td_thrinfo_t info;
    std::list<StackFrame *> stack;
    ThreadStack() {}
    void unwind(Process &, CoreRegisters &regs);
};

class Process : public ps_prochandle {
    Elf_Addr findRDebugAddr();
    void loadSharedObjects();
    char *vdso;
    CacheReader procio;
    Elf_Addr sysent; // for AT_SYSINFO
protected:
    td_thragent_t *agent;
    ElfObject *execImage;
    std::string abiPrefix;
    std::list<Reader *> readers; // readers allocated for objects.
    void processAUXV(const void *data, size_t len);
public:
    const Reader &io() const;
    std::map<Elf_Addr, ElfObject *> objects; // key=load address.
    virtual void load(); // loads shared objects, gets stack traces.
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) const = 0;
    void addElfObject(struct ElfObject *obj, Elf_Addr load);
    std::pair<Elf_Off, ElfObject *> findObject(Elf_Addr addr) const;
    Process(Reader &ex, Reader &mem);
    virtual void stop(pid_t lwpid) = 0;
    virtual void stopProcess() = 0;
    virtual void resume(pid_t lwpid) = 0;
    virtual pid_t getPID() const = 0;
    std::ostream &dumpStack(std::ostream &, const ThreadStack &);
    template <typename T> void listThreads(const T &);
    std::ostream &pstack(std::ostream &);
    Elf_Addr findNamedSymbol(const char *objectName, const char *symbolName) const;
    ~Process();
};

template <typename T> void
Process::listThreads(const T &callback)
{
    td_ta_thr_iter(agent,
            [] (const td_thrhandle_t *thr, void *v) -> int { T &callback = *(T *)v; callback(thr); return 0; },
            (void *)&callback, TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
}

enum ThreadState {
    stopped,
    running
};

struct ThreadInfo {
    ThreadState state;
    ThreadInfo() : state(running) {}
};

class LiveReader : public FileReader {
    pid_t pid;
    static std::string memname(pid_t);
public:
    virtual std::string describe() const {
        std::ostringstream os;
        os << "process pid " << pid;
        return os.str();
    }
    LiveReader(pid_t pid) : FileReader(memname(pid)) {}
};

class LiveProcess : public Process {
    pid_t pid;
    std::map<pid_t, ThreadInfo> lwps;
    friend class LiveReader;
    LiveReader liveIO;
public:
    LiveProcess(Reader &ex, pid_t pid);
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) const;
    virtual void stop(pid_t lwpid);
    virtual void resume(pid_t lwpid);
    virtual void load();
    virtual pid_t getPID()  const{ return pid; }
    void stopProcess() { stop(pid); }
};


class CoreProcess;
class CoreReader : public Reader {
    CoreProcess *p;
protected:
    virtual size_t read(off_t offset, size_t count, char *ptr) const;
public:
    CoreReader (CoreProcess *p);
    std::string describe() const;
};

struct CoreProcess : public Process {
    pid_t pid;
    ElfObject coreImage;
    CoreReader coreIO;
    friend class CoreReader;
public:
    CoreProcess(Reader &ex, Reader &core);
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) const;
    virtual void load();
    virtual void stop(lwpid_t);
    virtual void resume(lwpid_t);
    virtual pid_t getPID() const;
    void stopProcess() { }
};
