#include <elf.h>
extern "C" {
// Some thread_db headers are not safe to include unwrapped in extern "C"
#include <thread_db.h>
}

#include <map>
#include <set>
#include <sstream>
#include <functional>
#include <bitset>

#include "libpstack/ps_callback.h"
#include "libpstack/dwarf.h"

struct ps_prochandle {};

class Process;

namespace Dwarf {
struct StackFrame;
class ExpressionStack : public std::stack<Elf::Addr> {
public:
    bool isReg;
    int inReg;

    ExpressionStack(): isReg(false) {}
    Elf::Addr poptop() { Elf::Addr tos = top(); pop(); return tos; }
    Elf::Addr eval(const Process &, Dwarf::DWARFReader &r, const StackFrame*, Elf::Addr);
    Elf::Addr eval(const Process &, const Dwarf::Attribute &, const StackFrame*, Elf::Addr);
};

// this works for i386 and x86_64 - might need to change for other archs.
typedef unsigned long cpureg_t;

/*
 * The unwind mechanism tells us how this stack frame was created
 */
enum class UnwindMechanism {
   // this frame was created from machine state - it's the "top of stack".
   MACHINEREGS,

   // created by using DWARF unwinding information from previous.
   DWARF,

   // frame pointer register in previous frame.
   FRAMEPOINTER,

   // attempt was made to recover stack state by assuming the previous frame
   // was target of a call to a bad address
   BAD_IP_RECOVERY,

   // The previous frame was a signal "trampoline" - On receipt of a signal,
   // the kernel saved the processor state on the stack, and arranged for the
   // previous frame to be invoked. Unwinding requires decoding the register
   // state stored by the kernel on the stack.
   TRAMPOLINE,
};

struct StackFrame {
    Elf::Addr rawIP() const;
    Elf::Addr scopeIP() const;
    Elf::Addr cfa;
    std::map<unsigned, cpureg_t> regs;
    Elf::Object::sptr elf;
    Elf::Addr elfReloc;
    const Elf::Phdr *phdr;
    Info::sptr dwarf;
    CFI *frameInfo;
    const FDE *fde;
    const CIE *cie;
    Dwarf::DIE function;
    UnwindMechanism mechanism;
    StackFrame(UnwindMechanism mechanism)
        : cfa(0)
        , elfReloc(0)
        , phdr(0)
        , dwarf(0)
        , frameInfo(0)
        , fde(0)
        , cie(0)
        , mechanism(mechanism)
    {}
    StackFrame(const StackFrame &prev, UnwindMechanism mechanism)
       : StackFrame(mechanism)
       { regs = prev.regs; }
    StackFrame &operator = (const StackFrame &) = delete;
    void setReg(unsigned, cpureg_t);
    cpureg_t getReg(unsigned regno) const;
    Elf::Addr getCFA(const Process &, const CallFrame &) const;
    StackFrame *unwind(Process &p);
    void setCoreRegs(const Elf::CoreRegisters &);
    void getCoreRegs(Elf::CoreRegisters &) const;
    void getFrameBase(const Process &, intmax_t, ExpressionStack *) const;
};
}

struct ThreadStack {
    td_thrinfo_t info;
    std::vector<Dwarf::StackFrame *> stack;
    ThreadStack() {
        memset(&info, 0, sizeof info);
    }
    ~ThreadStack() {
        for (auto i = stack.begin(); i != stack.end(); ++i)
            delete *i;
    }
    void unwind(Process &, Elf::CoreRegisters &regs);
};

enum PstackOption {
    nosrc,
    doargs,
    nothreaddb,
    maxopt // leave this last
};

using PstackOptions = std::bitset<PstackOption::maxopt>;

/*
 * This contains information about an LWP.  In linux, since NPTL, this is
 * essentially a thread. Old style, userland threads may have a single LWP for
 * all threads.
 */
struct Lwp {
    int stopCount;
    timeval stoppedAt;
    Lwp() : stopCount{0}, stoppedAt{0,0} {}
};

typedef std::vector<std::pair<std::string, std::string>> PathReplacementList;
struct PrintableFrame;
class Process : public ps_prochandle {
    Elf::Addr findRDebugAddr();
    Elf::Addr entry;
    Elf::Addr interpBase;
    void loadSharedObjects(Elf::Addr);
    bool isStatic;
    Elf::Addr vdsoBase;

protected:
    td_thragent_t *agent;
    Elf::Object::sptr execImage;
    Elf::Object::sptr vdsoImage;
    std::string abiPrefix;
    const PathReplacementList &pathReplacements;

public:
    Elf::Addr sysent; // for AT_SYSINFO
    std::map<pid_t, Lwp> lwps;
    Dwarf::ImageCache &imageCache;
    std::map<Elf::Addr, Elf::Object::sptr> objects;
    void processAUXV(const Reader &);
    Reader::sptr io;

    virtual bool getRegs(lwpid_t pid, Elf::CoreRegisters *reg) = 0;
    void addElfObject(Elf::Object::sptr obj, Elf::Addr load);
    std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *>  findObject(Elf::Addr addr) const;
    Dwarf::Info::sptr getDwarf(Elf::Object::sptr);
    Process(Elf::Object::sptr exec, Reader::sptr memory, const PathReplacementList &prl, Dwarf::ImageCache &cache);
    virtual void stop(pid_t lwpid) = 0;
    virtual void stopProcess() = 0;
    virtual void findLWPs() = 0;

    virtual void resumeProcess() = 0;
    virtual void resume(pid_t lwpid) = 0;
    std::ostream &dumpStackText(std::ostream &, const ThreadStack &, const PstackOptions &) const;
    std::ostream &dumpFrameText(std::ostream &, const PrintableFrame &, Dwarf::StackFrame *) const;
    std::ostream &dumpStackJSON(std::ostream &, const ThreadStack &) const;
    template <typename T> void listThreads(const T &);
    Elf::Addr findSymbol(const char *symbolName, bool includeDebug,
          std::function<bool(Elf::Addr, const Elf::Object::sptr &)> matcher = [](Elf::Addr, const Elf::Object::sptr &) { return true; }) const;
    virtual ~Process();
    virtual void load(const PstackOptions &);
    virtual pid_t getPID() const = 0;
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

class LiveReader : public FileReader {
public:
    off_t size() const override { return std::numeric_limits<off_t>::max(); }
    LiveReader(pid_t, const std::string &);
};

// Name of the file /proc/<pid>/name, after symlink dereferencing
std::string procname(pid_t pid, const std::string &);

struct LiveThreadList;
class LiveProcess : public Process {
    pid_t pid;
    friend class LiveReader;
public:
    LiveProcess(Elf::Object::sptr &, pid_t, const PathReplacementList &, Dwarf::ImageCache &);
    virtual bool getRegs(lwpid_t pid, Elf::CoreRegisters *reg) override;
    virtual void stop(pid_t) override;
    virtual void resume(pid_t) override;
    void stopProcess() override;
    void resumeProcess() override;
    virtual void load(const PstackOptions &) override;
    virtual void findLWPs() override;
    virtual pid_t getPID() const override;
};

class CoreProcess;
class CoreReader : public Reader {
    CoreProcess *p;
protected:
    virtual size_t read(off_t remoteAddr, size_t size, char *ptr) const override;
public:
    CoreReader (CoreProcess *);
    virtual void describe(std::ostream &os) const override;
    off_t size() const override { return std::numeric_limits<off_t>::max(); }
    std::string filename() const override { return "process memory"; }
};

class CoreProcess : public Process {
    Elf::Object::sptr coreImage;
    friend class CoreReader;
public:
    CoreProcess(Elf::Object::sptr exec, Elf::Object::sptr core, const PathReplacementList &, Dwarf::ImageCache &);
    virtual bool getRegs(lwpid_t pid, Elf::CoreRegisters *reg) override;
    virtual void stop(lwpid_t) override;
    virtual void resume(lwpid_t) override;
    void stopProcess() override;
    void resumeProcess()  override { }
    virtual void findLWPs() override;
    virtual void load(const PstackOptions &) override;
    virtual pid_t getPID() const override;
};

// RAII to stop a process.
struct StopProcess {
    Process *proc;
public:
    StopProcess(Process *proc_) : proc(proc_) { proc->stopProcess(); }
    ~StopProcess() { proc->resumeProcess(); }
};

// RAII to stop a process.
struct StopLWP {
    Process *proc;
    lwpid_t lwp;
public:
    StopLWP(Process *proc_, lwpid_t lwp_) : proc(proc_), lwp(lwp_) { proc->stop(lwp); }
    ~StopLWP() { proc->resume(lwp); }
};
