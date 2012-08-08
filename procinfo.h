#include "elfinfo.h"
#include <sstream>

struct StackFrame {
    Elf_Addr ip;
    Elf_Addr bp;
    std::vector<Elf_Word> args;
    const char *unwindBy;
    StackFrame(Elf_Addr ip_, Elf_Addr bp_) : ip(ip_), bp(bp_), unwindBy(0) {}
};


typedef std::list<const td_thrhandle_t *> ThreadHandleList;
struct ThreadList : public ThreadHandleList {
public:
    ThreadList(Process &p);
};

struct ThreadStack {
    const td_thrhandle_t *handle;
    std::list<StackFrame *> stack;
    ThreadStack(const td_thrhandle_t *handle_) : handle(handle_) {}
    void unwind(Process &);
};

struct ps_prochandle : public Reader {
    td_thragent_t *agent;
    std::list<ElfObject *> objectList;
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
    virtual int getRegs(lwpid_t pid, CoreRegisters *reg) const = 0;
    void addElfObject(struct ElfObject *obj, Elf_Addr load);
    ElfObject *findObject(Elf_Addr addr) const;
    ps_prochandle(Reader &ex);
    virtual void stop(pid_t lwpid) const = 0;
    virtual void resume(pid_t lwpid) const = 0;
    virtual pid_t getPID() const = 0;
    ~ps_prochandle();
    void dumpStack(FILE *file, int indent, const ThreadStack &);
};

struct LiveProcess : public Process {
    pid_t pid;
    FILE *procMem;
protected:
    virtual void read(off_t offset, size_t count, char *ptr) const;
public:
    LiveProcess(Reader &ex, pid_t pid);
    virtual int getRegs(lwpid_t pid, CoreRegisters *reg) const;
    virtual void stop(pid_t lwpid) const;
    virtual void resume(pid_t lwpid) const;
    virtual void load();
    virtual pid_t getPID()  const{ return pid; }

    virtual std::string describe() const {
        std::ostringstream os;
        os << "process pid " << pid;
        return os.str();
    }
};

struct CoreProcess : public Process {
    pid_t pid;
    ElfObject coreImage;
    virtual void read(off_t offset, size_t count, char *ptr) const;
public:
    CoreProcess(Reader &ex, Reader &core);
    virtual int getRegs(lwpid_t pid, CoreRegisters *reg) const;
    virtual void load();
    virtual void stop(lwpid_t) const;
    virtual void resume(lwpid_t) const;
    virtual pid_t getPID() const;
    virtual std::string describe() const {
        std::ostringstream os;
        os << "process loaded from core " << coreImage.io;
        return os.str();
    }
};
