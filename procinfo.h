#include "elfinfo.h"

struct StackFrame {
    Elf_Addr ip;
    Elf_Addr bp;
    std::vector<Elf_Word> args;
    const char *unwindBy;
    StackFrame(Elf_Addr ip_, Elf_Addr bp_) : ip(ip_), bp(bp_), unwindBy(0) {}
};

struct Thread {
    int running;
    std::list<StackFrame *> stack;
    thread_t threadId;
    lwpid_t lwpid;
    Thread(Process *p, thread_t id, lwpid_t lwp, CoreRegisters regs);
    void stackUnwind(Process *, CoreRegisters &);
    ~Thread();
};

struct ps_prochandle {
    td_thragent_t *agent;
    std::list<ElfObject *> objectList;
    std::list<Thread *> threadList;
    ElfObject *execImage;
    std::string abiPrefix;
    PageCache pageCache;
    char *vdso;
    void loadSharedObjects();
    Elf_Addr findRDebugAddr();
    std::list<Reader *> readers; // readers allocated for objects.
public:
    virtual void load(); // loads shared objects, gets stack traces.
    virtual int getRegs(lwpid_t pid, CoreRegisters *reg) = 0;
    void addElfObject(struct ElfObject *obj, Elf_Addr load);
    ElfObject *findObject(Elf_Addr addr);
    ps_prochandle(Reader &ex);
    virtual size_t readMem(char *ptr, Elf_Addr remoteAddr, size_t count) = 0;
    void addThread(thread_t id, const CoreRegisters &, lwpid_t lwp);
    void dumpStacks(FILE *f, int indent);
    virtual void stop() = 0;
    virtual void resume() = 0;
    virtual pid_t getPID() = 0;
    ~ps_prochandle();
};

struct LiveProcess : public Process {
    pid_t pid;
public:
    LiveProcess(Reader &ex, pid_t pid);
    virtual int getRegs(lwpid_t pid, CoreRegisters *reg);
    virtual size_t readMem(char *ptr, Elf_Addr remoteAddr, size_t count);
    virtual void stop();
    virtual void resume();
    virtual pid_t getPID() { abort(); return -1; }
};

struct CoreProcess : public Process {
    pid_t pid;
    ElfObject coreImage;
public:
    CoreProcess(Reader &ex, Reader &core);
    virtual int getRegs(lwpid_t pid, CoreRegisters *reg);
    virtual size_t readMem(char *ptr, Elf_Addr remoteAddr, size_t count);
    virtual void load();
    virtual void stop() {}
    virtual void resume() {}
    virtual pid_t getPID();
};
