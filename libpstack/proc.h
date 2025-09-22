#ifndef libpstack_proc_h
#define libpstack_proc_h
#include <elf.h>
#include <signal.h>
#include <memory.h>
extern "C" {
    // Some thread_db headers are not safe to include unwrapped in extern "C"
#include <thread_db.h>
}

#include <map>
#include <set>
#include <stack>
#include <functional>
#include <optional>
#include <string_view>
#include <sys/stat.h> // for ino_t
#include <ucontext.h> // for gregset_t

#include "libpstack/ps_callback.h"
#include "libpstack/dwarf.h"

struct ps_prochandle {};

namespace pstack {
namespace Procman {

class Process;

class StackFrame;
class ExpressionStack : public std::stack<uintmax_t> {
public:
    bool isValue{false};
    int inReg{0};
    uintmax_t poptop() { auto tos = top(); pop(); return tos; }
    uintmax_t eval(Process &, Dwarf::DWARFReader &r, const StackFrame*, Elf::Addr);
    uintmax_t eval(Process &, const Dwarf::DIE::Attribute &, const StackFrame*, Elf::Addr);
};

// this works for i386 and x86_64 - might need to change for other archs.
using cpureg_t = unsigned long;

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

    // The stack frame was built up by scanning a log file.
    LOGFILE,

    INVALID,
};

// Information for a specific location in memory
// XXX: much of this should be per-ELF file, and cached with the elf object.

class CodeLocation {
    Elf::Addr location_; // object-relative location.
    Dwarf::Info::sptr dwarf_;
    const Elf::Phdr *phdr_;
    mutable const Dwarf::CIE *cie_;
    mutable const Dwarf::FDE *fde_;
    mutable const Dwarf::CFI *cfi_;
    Dwarf::CallFrame frame_;
    mutable Dwarf::DIE die_;
    mutable Elf::MaybeNamedSymbol symbol_;

public:
    const Elf::Phdr &phdr() const { return *phdr_; }
    Elf::Addr location() const { return location_; }
    std::vector<std::pair<std::string, int>> source() const;
    const Elf::MaybeNamedSymbol &symbol() const;
    Dwarf::Info::sptr dwarf() { return dwarf_; }
    explicit operator bool() const;
    const Dwarf::DIE &die() const;
    const Dwarf::CIE *cie() const;
    const Dwarf::FDE *fde() const;
    Dwarf::CFI *cfi() const;
    CodeLocation();
    CodeLocation(Dwarf::Info::sptr, const Elf::Phdr *, Elf::Addr location);
};

// This is a CodeLocation, but relocated for a process address.
class ProcessLocation {
    Elf::Addr location_; // process-relative location.

public:
    // XXX: can cache these in Dwarf::Info
    std::shared_ptr<CodeLocation> codeloc;
    ProcessLocation(Process &proc, Elf::Addr address_);

    // returns true if the location has been located in an ELF object.
    [[nodiscard]] bool inObject() const  { return codeloc != nullptr; }

    // these are proxies or the CodeLocation, adjusted by the elfReloc value.
    [[nodiscard]] const Dwarf::DIE &die() const { return codeloc ? codeloc->die() : Dwarf::DIE::null; }
    [[nodiscard]] const Dwarf::FDE *fde() const { return codeloc ? codeloc->fde() : nullptr; }
    [[nodiscard]] const Dwarf::CIE *cie() const;
    [[nodiscard]] const Dwarf::CFI *cfi() const;
    // Returns the load address of the ELF object that contains this address.
    // Or zero if there is not ELF object found for this address.
    [[nodiscard]] Elf::Addr elfReloc() const { return codeloc == nullptr ? 0 : location_ - codeloc->location(); }
    [[nodiscard]] Elf::Object::sptr elf() const { return codeloc ? codeloc->dwarf()->elf : nullptr; }

    [[nodiscard]] Elf::MaybeNamedSymbol symbol() const;
    [[nodiscard]] std::vector<std::pair<std::string, int>> source() const;

    [[nodiscard]] Elf::Addr objLocation() const { return codeloc->location(); }
    [[nodiscard]] Elf::Addr location() const { return location_; }
    [[nodiscard]] Dwarf::Info::sptr dwarf() const { return codeloc ? codeloc->dwarf() : nullptr; }
};

class StackFrame {
public:
    [[nodiscard]] Elf::Addr rawIP() const;
    ProcessLocation scopeIP(Process &) const;
    CoreRegisters regs;
    Elf::Addr cfa;
    UnwindMechanism mechanism;

    // This frame is a signal trampoline, eg, at a function like
    // __kernel_rt_sigreturn
    bool isSignalTrampoline{};

    // This frame was unwound from a signal trampoline - implying didn't call
    // the function above it on the stack.
    bool unwoundFromTrampoline{};

    StackFrame(UnwindMechanism mechanism, const CoreRegisters &regs);

    std::optional<CoreRegisters> unwind(Process &);
    uintptr_t getFrameBase(Process &) const;
};

// Descriptive data useful for formatting frame content.
struct PrintableFrame {
    Process &proc;
    std::string dieName;
    Elf::Addr functionOffset;
    const StackFrame &frame;
    std::vector<Dwarf::DIE> inlined; // all inlined functions at this address.

    PrintableFrame(Process &, const StackFrame &frame);

    auto operator = (const PrintableFrame &) = delete;
    auto operator = (PrintableFrame &&) = delete;
    PrintableFrame(const PrintableFrame &) = delete;
    ~PrintableFrame() = default;
    PrintableFrame(PrintableFrame &&) = delete;
    
};

struct ThreadStack {
    td_thrinfo_t info {};
    std::optional<std::string> name;
    std::vector<StackFrame> stack;
    void unwind(Process &, const CoreRegisters &regs);
};

struct DevNode {
    int major = -1;
    int minor = -1;
    uintmax_t inode = 0;
    std::string path;
    bool operator == (const DevNode &rhs) const {
        return major == rhs.major && minor == rhs.minor && inode == rhs.inode;
    }
};

struct AddressRange {
    Elf::Addr start;
    Elf::Addr end;
    Elf::Addr fileEnd;
    uintmax_t offset;
    DevNode backing;

    enum class VmFlag {
       readable, writeable, executable, shared, may_read, may_write,
       may_execute, may_share, stack_grows_down, pure_pfn_range,
       disabled_write, pages_locked, memory_mapped_io, sequential_read_advised,
       random_read_advised, dont_copy_on_fork, dont_expand_on_remap,
       accountable, swap_not_reserved, huge_tlb_pages, synchronous_page_fault,
       architecture_specific, wipe_on_fork, dont_dump, soft_dirty, mixed_map,
       huge_page_advised, no_huge_page_advised, mergeable_advised,
       arm64_BTI_guarded_page, arm64_MTE_allocation_tags,
       userfaultfd_missing_tracking, userfaultfd_wr_protect_tracking,
       shadow_stack, sealed
    };
    static std::optional<VmFlag> vmflag(std::string_view);

    enum class Permission { read,write,exec,priv,count, shared };
    std::set<Permission> permissions;
    std::set<VmFlag> vmflags;
};

using AddressSpace = std::vector<AddressRange>;

// An ELF object mapped at an address. We don't actually create the Elf::Object
// until the first time you call "object" here. This avoids needless I/O, esp.
// on resource constrained systems.
struct MappedObject {
    std::string name_;
    Elf::BuildID bid_;
    Elf::Object::sptr objptr_;
public:
    [[nodiscard]] const std::string &name() const { return name_; }
    bool operator < (const MappedObject &rhs) const {
        return name_ < rhs.name_ || ( name_ == rhs.name_ && bid_ < rhs.bid_); // for comparing pairs.
    }
    Elf::Object::sptr object(Context &ctx) {
        if (objptr_ == nullptr)
            objptr_ = ctx.findImage(bid_);
        if (objptr_ == nullptr)
            objptr_ = ctx.findImage(name_);
        return objptr_;
    }
    MappedObject(std::string_view name, Elf::BuildID bid, Elf::Object::sptr objptr = {}) :
       name_{name}, bid_{std::move(bid)}, objptr_{std::move(objptr)} {}
};

class Process : public ps_prochandle {
    Elf::Addr entry{};
    Elf::Addr dt_debug{};
    Elf::Addr interpBase{};
    Elf::Addr vdsoBase{};
    Elf::Addr execBase{};
    void loadSharedObjects(Elf::Addr);
    Elf::Addr extractDtDebugFromDynamicSegment(const Elf::Phdr &phdr, Elf::Addr loadAddr, const char *);
    void processAUXV(const Reader &);

protected:
    td_thragent_t *agent;
    static AddressSpace procAddressSpace(const std::string &fn); //  utility to parse contents of /proc/pid/maps
    virtual bool loadSharedObjectsFromFileNote() = 0;
    [[nodiscard]] virtual std::optional<std::string> getTaskName( lwpid_t ) const;

public:
    [[nodiscard]] Elf::Addr getVdsoBase() const { return vdsoBase; };
    std::map<Elf::Addr, MappedObject> objects;
    Elf::Object::sptr execImage;
    Elf::Object::sptr vdsoImage;
    Context &context;
    Reader::sptr io;

    std::pair<Elf::Addr, Elf::Object::sptr> getElfObject(Elf::Addr addr);
    [[nodiscard]] virtual Reader::csptr getAUXV() const = 0;
    virtual Elf::Addr findRDebugAddr();

    virtual size_t getRegs(lwpid_t pid, int code, size_t size, void *data) = 0;

    template <typename T, int code> size_t getRegset(lwpid_t pid, T &reg) {
        return getRegs(pid, code, sizeof (T), reinterpret_cast<void *>( &reg ) );
    }
    CoreRegisters getCoreRegs(lwpid_t lwp);

    [[nodiscard]] virtual std::optional<siginfo_t> getSignalInfo() const = 0;

    void addElfObject(std::string_view, const Elf::Object::sptr &, Elf::Addr load);
    // Find the the object (and its load address) and segment containing a given address
    std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *> findSegment(Elf::Addr addr);
    [[nodiscard]] Dwarf::Info::sptr getDwarf(Elf::Object::sptr) const;
    Process(Context &ctx, Elf::Object::sptr exec, Reader::sptr memory );
    virtual void stop(pid_t lwpid) = 0;
    virtual void stopProcess() = 0;
    virtual void resumeProcess() = 0;
    virtual void resume(pid_t lwpid) = 0;
    virtual Elf::Object::sptr executableImage() { return nullptr; }
    std::ostream &dumpStackText(std::ostream &, const ThreadStack &);
    std::ostream &dumpFrameText(std::ostream &, const StackFrame &, int);
    template <typename T> void listThreads(const T &invokeable);
    virtual void listLWPs(const std::function<void(lwpid_t)> &) {};

    // find address of named symbol in the process.
    Elf::Addr resolveSymbol(const char *symbolName, bool includeDebug,
            std::function<bool(std::string_view)> matcher = [](std::string_view) { return true; });

    // find symbol data of named symbol in the process.
    // like resolveSymbol, but return the library and that library's load address as well as the address in the process.
    std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Sym>
        resolveSymbolDetail(const char *name, bool includeDebug,
                std::function<bool(std::string_view)> match = [](std::string_view) { return true; });
    virtual std::list<ThreadStack> getStacks();
    void load();
    [[nodiscard]] virtual pid_t getPID() const = 0;
    [[nodiscard]] virtual AddressSpace addressSpace() const = 0;
    static std::shared_ptr<Process> load(Context &ctx, Elf::Object::sptr exe, std::string id);
    virtual ~Process();
    Process(const Process &) = delete;
    Process(Process &&) = delete;
    Process &operator = (const Process &) = delete;
    Process &operator = (Process &&) = delete;
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
    Off size() const override { return std::numeric_limits<Off>::max(); }
    LiveReader(Context &, pid_t, const std::string &);
};

struct LiveThreadList;
class LiveProcess final : public Process {
    pid_t pid;

    struct Lwp {
        int stopCount = 0;
        int ptraceErr = 0; // 0 if ptrace worked, otherwise, errno.
        timeval stoppedAt { .tv_sec = 0, .tv_usec = 0 };
    };
    std::map<pid_t, Lwp> stoppedLWPs;
public:
    // attach to existing process.
    LiveProcess(Context &, Elf::Object::sptr &, pid_t, bool alreadyStopped=false);
    LiveProcess(const LiveProcess &) = delete;
    LiveProcess(LiveProcess &&) = delete;
    LiveProcess &operator = (const LiveProcess &) = delete;
    LiveProcess &operator = (LiveProcess &&) = delete;
    ~LiveProcess() override;

    void listLWPs(const std::function<void(lwpid_t)> &invokeable) override;
    size_t getRegs(lwpid_t pid, int code, size_t sz, void *reg) override;
    void stop(pid_t pid) override;
    void resume(pid_t pid) override;
    void stopProcess() override;
    void resumeProcess() override;
    [[nodiscard]] Reader::csptr getAUXV() const override;
    [[nodiscard]] pid_t getPID() const override;
    [[nodiscard]] Elf::Object::sptr executableImage() override;
    [[nodiscard]] std::optional<siginfo_t> getSignalInfo() const override;
protected:
    bool loadSharedObjectsFromFileNote() override;
    [[nodiscard]] std::vector<AddressRange> addressSpace() const override;
    std::optional<std::string> getTaskName( lwpid_t task ) const override;
};


class SelfProcess : public Process {
    pid_t pid;
public:
    // attach to existing process.
    explicit SelfProcess(Context &, const Elf::Object::sptr & = nullptr);
    void listLWPs(const std::function<void(lwpid_t)> &invoke) override;
    size_t getRegs(lwpid_t pid, int code, size_t sz, void *reg) override;
    void stop(pid_t pid) override;
    void resume(pid_t pid) override;
    void stopProcess() override;
    void resumeProcess() override;
    [[nodiscard]] Reader::csptr getAUXV() const override;
    [[nodiscard]] pid_t getPID() const override;
    [[nodiscard]] std::optional<siginfo_t> getSignalInfo() const override { return std::nullopt; }
protected:
    Elf::Addr findRDebugAddr() override;
    bool loadSharedObjectsFromFileNote() override;
    [[nodiscard]] std::vector<AddressRange> addressSpace() const override;
};

class CoreProcess;
class CoreReader final : public Reader {
    Process *p;
    Elf::Object::sptr core;
protected:
    size_t read(Off remoteAddr, size_t size, char *ptr) const override;
public:
    CoreReader (Process *, Elf::Object::sptr);
    void describe(std::ostream &os) const override;
    Off size() const override { return std::numeric_limits<Off>::max(); }
    std::string filename() const override { return "process memory"; }
};

class CoreProcess final : public Process {
    std::vector<Elf::NoteDesc> notes;
    std::map<lwpid_t, size_t> lwpToPrStatusIdx;
    prpsinfo_t prpsinfo;
public:
    Elf::Object::sptr coreImage;
    CoreProcess(Context &, Elf::Object::sptr exec, Elf::Object::sptr core);
    size_t getRegs(lwpid_t pid, int code, size_t sz, void *regs) override;
    void stop(lwpid_t lwp) override;
    void resume(lwpid_t lwp) override;
    void stopProcess() override;
    void resumeProcess()  override { }
    [[nodiscard]] Reader::csptr getAUXV() const override;
    [[nodiscard]] pid_t getPID() const override;
    void listLWPs(const std::function<void(lwpid_t)> &invoke) override;
    [[nodiscard]] std::optional<siginfo_t> getSignalInfo() const override;
protected:
    bool loadSharedObjectsFromFileNote() override;
    [[nodiscard]] std::vector<AddressRange> addressSpace() const override;
};

// RAII to stop a process.
struct StopProcess {
    Process *proc;
public:
    explicit StopProcess(Process *proc_) : proc(proc_) { proc->stopProcess(); }
    StopProcess(const StopProcess &) = delete;
    StopProcess(StopProcess &&) = delete;
    auto &operator = (const StopProcess &) = delete;
    auto &operator = (StopProcess &&) = delete;
    void clear() {
        if (bool(proc)) {
            proc->resumeProcess();
            proc = nullptr;
        }
    }
    ~StopProcess() { clear(); }
};

// RAII to stop a thread.
struct StopLWP {
    Process *proc;
    lwpid_t lwp;
public:
    StopLWP(const StopLWP &) = delete;
    StopLWP(StopLWP &&) = delete;
    StopLWP & operator = (const StopLWP &) = delete;
    StopLWP & operator = (StopLWP &&) = delete;
    StopLWP(Process *proc_, lwpid_t lwp_) : proc(proc_), lwp(lwp_) { proc->stop(lwp); }
    ~StopLWP() { proc->resume(lwp); }
};

// Types for the NT_FILE note.
struct FileNoteHeader {
    Elf::Off count;
    Elf::Off pageSize;
};

struct WaitStatus {
    int status;
    explicit WaitStatus(int status) : status{status}{}
};

struct SigInfo {
   const siginfo_t &si;
};
std::ostream &operator << (std::ostream &os, const SigInfo &);
std::ostream &operator << (std::ostream &os, WaitStatus ws);
}

std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::StackFrame, pstack::Procman::Process *> &jt);
std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::ThreadStack, pstack::Procman::Process *> &jt);

}

#endif
