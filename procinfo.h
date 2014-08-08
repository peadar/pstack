#include "elfinfo.h"
#include "dwarf.h"
#include <map>
#include <set>
#include <sstream>
#include <functional>
#include <bitset>

struct ps_prochandle {};

class Process;

struct StackFrame {
    Elf_Addr ip;
    std::vector<Elf_Word> args;
    const char *unwindBy;
    StackFrame(Elf_Addr ip_) : ip(ip_), unwindBy("ERROR") {}
};

struct ThreadStack {
    td_thrinfo_t info;
    std::vector<StackFrame *> stack;
    ThreadStack() {}
    ~ThreadStack() {
        for (auto i = stack.begin(); i != stack.end(); ++i)
            delete *i;
    }
    void unwind(Process &, CoreRegisters &regs);
};


class PstackOptions {
public:
    enum PstackOption {
        nosrc = 1 << 0,
        maxopt = 1 << 1
    };
    void operator += (PstackOption);
    void operator -= (PstackOption);
    bool operator() (PstackOption) const;
    std::bitset<maxopt> values;
};

typedef std::vector<std::pair<std::string, std::string>> PathReplacementList;
class Process : public ps_prochandle {
    Elf_Addr findRDebugAddr();
    Elf_Off entry; // entrypoint of process.
    void loadSharedObjects(Elf_Addr);
    char *vdso;
    bool isStatic;
    Elf_Addr sysent; // for AT_SYSINFO
    std::map<std::shared_ptr<ElfObject>, std::unique_ptr<DwarfInfo>> dwarf;

protected:
    td_thragent_t *agent;
    std::shared_ptr<ElfObject> execImage;
    std::string abiPrefix;
    PathReplacementList pathReplacements;
public:
    void processAUXV(const void *data, size_t len);
    std::shared_ptr<Reader> io;
    struct LoadedObject {
        Elf_Off reloc;
        std::shared_ptr<ElfObject> object;
        LoadedObject(Elf_Off reloc_, std::shared_ptr<ElfObject> object_) : reloc(reloc_), object(object_) {}
    };
    std::vector<LoadedObject> objects;
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) const = 0;
    void addElfObject(std::shared_ptr<ElfObject> obj, Elf_Addr load);
    LoadedObject findObject(Elf_Addr addr) const;
    std::unique_ptr<DwarfInfo> &getDwarf(std::shared_ptr<ElfObject>);
    Process(std::shared_ptr<ElfObject> obj, std::shared_ptr<Reader> mem, const PathReplacementList &prl);
    virtual void stop(pid_t lwpid) = 0;
    virtual void stopProcess() = 0;

    virtual void resumeProcess() = 0;
    virtual void resume(pid_t lwpid) = 0;
    virtual pid_t getPID() const = 0;
    std::ostream &dumpStackText(std::ostream &, const ThreadStack &, const PstackOptions &);
    std::ostream &dumpStackJSON(std::ostream &, const ThreadStack &);
    template <typename T> void listThreads(const T &);
    std::ostream &pstack(std::ostream &, const PstackOptions &options);
    Elf_Addr findNamedSymbol(const char *objectName, const char *symbolName) const;
    ~Process();
    virtual void load();
};

template <typename T> int
threadListCb(const td_thrhandle_t *thr, void *v)
{ T &callback = *(T *)v; callback(thr); return 0; }

template <typename T> void
Process::listThreads(const T &callback)
{
    td_ta_thr_iter(agent,
            threadListCb<T>,
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
    std::string base;
    static std::string procname(pid_t, std::string base);
public:
    static std::shared_ptr<Reader> procfile(pid_t, std::string base);
    virtual std::string describe() const {
        std::ostringstream os;
        os << base << " for process pid " << pid;
        return os.str();
    }
    LiveReader(pid_t pid_, std::string base_) : FileReader(procname(pid_, base_)), pid(pid_), base(base_) {}
};

class LiveProcess : public Process {
    pid_t pid;
    std::map<pid_t, ThreadInfo> stoppedLwps;
    friend class LiveReader;
    int stopCount;
    timeval start;
    std::set<pid_t> lwps; // lwps we could not suspend.
public:
    LiveProcess(std::shared_ptr<ElfObject> ex, pid_t pid);
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) const;
    virtual void stop(pid_t lwpid);
    virtual void resume(pid_t lwpid);
    virtual pid_t getPID()  const{ return pid; }
    void stopProcess();
    void resumeProcess();
    virtual void load();
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
    std::shared_ptr<ElfObject> coreImage;
    friend class CoreReader;
public:
    CoreProcess(std::shared_ptr<ElfObject> exec, std::shared_ptr<ElfObject> core,
            const std::vector<std::pair<std::string, std::string>> &);
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) const;
    virtual void stop(lwpid_t);
    virtual void resume(lwpid_t);
    virtual pid_t getPID() const;
    void stopProcess() { }
    void resumeProcess() { }
    virtual void load();
};
