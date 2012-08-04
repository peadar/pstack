#include "elfinfo.h"
#include <sstream>

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

struct ps_prochandle : public Reader {
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
    void addVDSOfromAuxV(const void *data, size_t len);
    virtual void load(); // loads shared objects, gets stack traces.
    virtual int getRegs(lwpid_t pid, CoreRegisters *reg) = 0;
    void addElfObject(struct ElfObject *obj, Elf_Addr load);
    ElfObject *findObject(Elf_Addr addr);
    ps_prochandle(Reader &ex);
    void addThread(thread_t id, const CoreRegisters &, lwpid_t lwp);
    void dumpStacks(FILE *f, int indent);
    virtual void stop() = 0;
    virtual void resume() = 0;
    virtual pid_t getPID() = 0;
    ~ps_prochandle();
};

struct LiveProcess : public Process {
    pid_t pid;
    FILE *procMem;
protected:
    virtual void read(off_t offset, size_t count, char *ptr);
public:
    LiveProcess(Reader &ex, pid_t pid);
    virtual int getRegs(lwpid_t pid, CoreRegisters *reg);
    virtual void stop();
    virtual void resume();
    virtual void load();
    virtual pid_t getPID() { return pid; }

    virtual std::string describe() const {
        std::ostringstream os;
        os << "process pid " << pid;
        return os.str();
    }
};

struct CoreProcess : public Process {
    pid_t pid;
    ElfObject coreImage;
    virtual void read(off_t offset, size_t count, char *ptr);
public:
    CoreProcess(Reader &ex, Reader &core);
    virtual int getRegs(lwpid_t pid, CoreRegisters *reg);
    virtual void load();
    virtual void stop() {}
    virtual void resume() {}
    virtual pid_t getPID();

    virtual std::string describe() const {
        std::ostringstream os;
        os << "process loaded from core " << coreImage.io;
        return os.str();
    }

};
