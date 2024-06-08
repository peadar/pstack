#ifndef libpstack_proc_h
#define libpstack_proc_h
#include <elf.h>
#include <memory.h>
extern "C" {
    // Some thread_db headers are not safe to include unwrapped in extern "C"
#include <thread_db.h>
}

#include <map>
#include <variant>
#include <set>
#include <stack>
#include <functional>
#include <optional>
#include <string_view>
#include <ucontext.h> // for gregset_t

#include "libpstack/ps_callback.h"
#include "libpstack/dwarf.h"

struct ps_prochandle {};

struct PstackOptions {
    bool nosrc = false;
    bool doargs = false;
    bool dolocals = false;
    bool nothreaddb = false;
    bool nodienames = false; // don't use names from DWARF dies in backtraces.
    int maxdepth = std::numeric_limits<int>::max();
    int maxframes = 20;
    std::ostream *output = &std::cout;
};

namespace pstack::Procman {

class Process;

class StackFrame;
class ExpressionStack : public std::stack<uintmax_t> {
public:
    bool isValue;
    int inReg;
    ExpressionStack(): isValue(false) {}
    uintmax_t poptop() { auto tos = top(); pop(); return tos; }
    uintmax_t eval(Process &, Dwarf::DWARFReader &r, const StackFrame*, Elf::Addr);
    uintmax_t eval(Process &, const Dwarf::DIE::Attribute &, const StackFrame*, Elf::Addr);
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

    // The stack frame was built up by scanning a log file.
    LOGFILE,

    INVALID,
};

// Information for a specific location in memory
// XXX: much of this should be per-ELF file, and cached with the elf object.

struct CodeLocation {
    Elf::Addr location_;
    Dwarf::Info::sptr dwarf_;
    const Elf::Phdr *phdr_;
    mutable const Dwarf::CIE *cie_;
    mutable const Dwarf::FDE *fde_;
    mutable const Dwarf::CFI *cfi_;
    Dwarf::CallFrame frame_;
    mutable Dwarf::DIE die_;
    mutable Elf::MaybeNamedSymbol symbol_;

    std::vector<std::pair<std::string, int>> source() const;
    const Elf::MaybeNamedSymbol &symbol() const;

    operator bool() const;
    const Dwarf::DIE &die() const;
    const Dwarf::CIE *cie() const;
    const Dwarf::FDE *fde() const;
    Dwarf::CFI *cfi() const;
    CodeLocation();
    CodeLocation(Dwarf::Info::sptr, const Elf::Phdr *, Elf::Addr location);
};

// This is a CodeLocation, but relocated for a process address.
struct ProcessLocation {
    Elf::Addr location;

    // XXX: can cache these in Dwarf::Info
    std::shared_ptr<CodeLocation> codeloc;

    void set(Process &proc, Elf::Addr address);
    ProcessLocation(Process &proc, Elf::Addr address_);

    // returns true if the location has been located in an ELF object.
    bool inObject() const  {
        return codeloc != nullptr;
    }
    // these are proxies or the CodeLocation, adjusted by the elfReloc value.
    const Dwarf::DIE &die() const;
    const Dwarf::CIE *cie() const;
    const Dwarf::FDE *fde() const;
    const Dwarf::CFI *cfi() const;
    Elf::MaybeNamedSymbol symbol() const;
    std::vector<std::pair<std::string, int>> source() const;
    Elf::Object::sptr elf() const { return codeloc ? codeloc->dwarf_->elf : nullptr; }

    // Returns the load address of the ELF object that contains this address.
    // Or zero if there is not ELF object found for this address.
    Elf::Addr elfReloc() const {
        if (codeloc == nullptr)
            return 0;
        return location - codeloc->location_;
    }
    Elf::Addr objLocation() const { return codeloc->location_; }
    Elf::Addr address() { return location; }
    Dwarf::Info::sptr dwarf() const { return codeloc ? codeloc->dwarf_ : nullptr; }
};

class StackFrame {
public:
    Elf::Addr rawIP() const;
    ProcessLocation scopeIP(Process &) const;
    Elf::CoreRegisters regs;
    Elf::Addr cfa;
    UnwindMechanism mechanism;
    bool isSignalTrampoline;
    StackFrame(UnwindMechanism mechanism, const Elf::CoreRegisters &regs);
    StackFrame &operator = (const StackFrame &) = default;
    StackFrame(const StackFrame &) = default;
    std::optional<Elf::CoreRegisters> unwind(Process &);
    void setCoreRegs(const Elf::CoreRegisters &);
    void getCoreRegs(Elf::CoreRegisters &) const;
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
    PrintableFrame(const PrintableFrame &) = delete;
    PrintableFrame() = delete;
};

struct ThreadStack {
    td_thrinfo_t info;
    std::vector<StackFrame> stack;
    ThreadStack() {
        memset(&info, 0, sizeof info);
    }
    void unwind(Process &, Elf::CoreRegisters &regs);
};

struct PrintableFrame;

struct DevNode {
    int major = -1;
    int minor = -1;
    unsigned long inode = -1;
    std::string path;
    bool operator == (const DevNode &rhs) const {
        return major == rhs.major && minor == rhs.minor && inode == rhs.inode;
    }
};

struct AddressRange {
    Elf::Addr start;
    Elf::Addr end;
    Elf::Addr fileEnd;
    off_t offset;
    DevNode backing;

    enum class Flags { read,write,exec,priv,count, shared };
    std::set<Flags> permissions;
};

// An ELF object mapped at an address. We don't actually create the Elf::Object
// until the first time you call "object" here. This avoids needless I/O, esp.
// on resource constrained systems.
struct MappedObject {
    std::string name_;
    Elf::Object::sptr objptr_;
public:
    const std::string &name() { return name_; }
    bool operator < (const MappedObject &rhs) const {
        return name_ < rhs.name_; // for comparing pairs.
    }
    Elf::Object::sptr object(Dwarf::ImageCache &cache) {
        if (objptr_ == nullptr) {
            objptr_ = cache.getImageForName(name_);
        }
        return objptr_;
    }
    MappedObject(std::string_view name, const Elf::Object::sptr &objptr = {})
        : name_{name}, objptr_{objptr} {}
};

class Process : public ps_prochandle {
    Elf::Addr entry;
    Elf::Addr interpBase;
    void loadSharedObjects(Elf::Addr);
public:
    std::map<Elf::Addr, MappedObject> objects;
    Elf::Addr vdsoBase;
    virtual Elf::Addr findRDebugAddr();

protected:
    virtual bool loadSharedObjectsFromFileNote() = 0;
    td_thragent_t *agent;
public:
    Elf::Object::sptr execImage;
    Elf::Object::sptr vdsoImage;
protected:
    std::string abiPrefix;
    static std::vector<AddressRange> procAddressSpace(const std::string &fn); //  utility to parse contents of /proc/pid/maps

public:
    std::pair<Elf::Addr, Elf::Object::sptr> getElfObject(Elf::Addr addr);
    PstackOptions options;
    Elf::Addr sysent; // for AT_SYSINFO
    Dwarf::ImageCache &imageCache;
    virtual Reader::csptr getAUXV() const = 0;
    void processAUXV(const Reader &);
    Reader::sptr io;

    virtual size_t getRegs(lwpid_t pid, int code, size_t size, void *data) = 0;

    template <typename T, int code> size_t getRegset(lwpid_t pid, T &reg) {
        return getRegs(pid, code, sizeof (T), reinterpret_cast<void *>( &reg ) );
    }


    void addElfObject(std::string_view, const Elf::Object::sptr &, Elf::Addr load);
    // Find the the object (and its load address) and segment containing a given address
    std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *> findSegment(Elf::Addr addr);
    Dwarf::Info::sptr getDwarf(Elf::Object::sptr) const;
    Process(Elf::Object::sptr exec, Reader::sptr memory, const PstackOptions &prl, Dwarf::ImageCache &cache);
    virtual void stop(pid_t lwpid) = 0;
    virtual void stopProcess() = 0;
    virtual void resumeProcess() = 0;
    virtual void resume(pid_t lwpid) = 0;
    std::ostream &dumpStackText(std::ostream &, const ThreadStack &);
    std::ostream &dumpFrameText(std::ostream &, const StackFrame &, int);
    template <typename T> void listThreads(const T &);
    virtual void listLWPs(std::function<void(lwpid_t)>) {};


    // find address of named symbol in the process.
    Elf::Addr resolveSymbol(const char *symbolName, bool includeDebug,
            std::function<bool(std::string_view)> matcher = [](std::string_view) { return true; });

    // find symbol data of named symbol in the process.
    // like resolveSymbol, but return the library and that library's load address as well as the address in the process.
    std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Sym>
        resolveSymbolDetail(const char *name, bool includeDebug,
                std::function<bool(std::string_view)> match = [](std::string_view) { return true; });
    virtual std::list<ThreadStack> getStacks();
    virtual ~Process();
    void load();
    virtual pid_t getPID() const = 0;
    virtual std::vector<AddressRange> addressSpace() const = 0;
    static std::shared_ptr<Process> load(Elf::Object::sptr exe, std::string id, const PstackOptions &options, Dwarf::ImageCache &cache);
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
    LiveReader(pid_t, const std::string &);
};

// Name of the file /proc/<pid>/name, after symlink dereferencing
std::string procname(pid_t pid, const std::string &);

struct LiveThreadList;
class LiveProcess final : public Process {
    pid_t pid;

    struct Lwp {
        int stopCount = 0;
        int ptraceErr = 0; // 0 if ptrace worked, otherwise, errno.
        timeval stoppedAt { 0, 0 };
    };
    std::map<pid_t, Lwp> stoppedLWPs;
public:
    // attach to existing process.
    LiveProcess(Elf::Object::sptr &, pid_t, const PstackOptions &, Dwarf::ImageCache &, bool alreadyStopped=false);
    ~LiveProcess();

    void listLWPs(std::function<void(lwpid_t)>) override;
    virtual size_t getRegs(lwpid_t pid, int code, size_t sz, void *reg) override;
    virtual void stop(pid_t) override;
    virtual void resume(pid_t) override;
    void stopProcess() override;
    void resumeProcess() override;
    virtual Reader::csptr getAUXV() const override;
    virtual pid_t getPID() const override;
protected:
    bool loadSharedObjectsFromFileNote() override;
    std::vector<AddressRange> addressSpace() const override;
};


class SelfProcess : public Process {
    pid_t pid;
public:
    // attach to existing process.
    SelfProcess(const Elf::Object::sptr &, const PstackOptions &, Dwarf::ImageCache &);
    void listLWPs(std::function<void(lwpid_t)>) override;
    virtual size_t getRegs(lwpid_t pid, int code, size_t sz, void *reg) override;
    virtual void stop(pid_t) override;
    virtual void resume(pid_t) override;
    void stopProcess() override;
    void resumeProcess() override;
    virtual Reader::csptr getAUXV() const override;
    virtual pid_t getPID() const override;
protected:
    virtual Elf::Addr findRDebugAddr() override;
    bool loadSharedObjectsFromFileNote() override;
    std::vector<AddressRange> addressSpace() const override;
};

class CoreProcess;
class CoreReader final : public Reader {
    Process *p;
    Elf::Object::sptr core;
protected:
    virtual size_t read(Off remoteAddr, size_t size, char *ptr) const override;
public:
    CoreReader (Process *, Elf::Object::sptr);
    virtual void describe(std::ostream &os) const override;
    Off size() const override { return std::numeric_limits<Off>::max(); }
    std::string filename() const override { return "process memory"; }
};

class CoreProcess final : public Process {
    std::vector<Elf::NoteDesc> notes;
    std::map<lwpid_t, size_t> lwpToPrStatusIdx;
    prpsinfo_t prpsinfo;
public:
    Elf::Object::sptr coreImage;
    CoreProcess(Elf::Object::sptr exec, Elf::Object::sptr core, const PstackOptions &, Dwarf::ImageCache &);
    virtual size_t getRegs(lwpid_t pid, int code, size_t sz, void *regs) override;
    virtual void stop(lwpid_t) override;
    virtual void resume(lwpid_t) override;
    void stopProcess() override;
    void resumeProcess()  override { }
    virtual Reader::csptr getAUXV() const override;
    virtual pid_t getPID() const override;
    void listLWPs(std::function<void(lwpid_t)>) override;
protected:
    bool loadSharedObjectsFromFileNote() override;
    std::vector<AddressRange> addressSpace() const override;
};

// RAII to stop a process.
struct StopProcess {
    Process *proc;
public:
    StopProcess(Process *proc_) : proc(proc_) { proc->stopProcess(); }
    void clear() {
        if (proc) {
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
    StopLWP(Process *proc_, lwpid_t lwp_) : proc(proc_), lwp(lwp_) { proc->stop(lwp); }
    ~StopLWP() { proc->resume(lwp); }
};

// Types for the NT_FILE note.
struct FileNoteHeader {
    Elf::Off count;
    Elf::Off pageSize;
};

struct FileEntry {
    Elf::Off start;
    Elf::Off end;
    Elf::Off fileOff;
};

class FileEntries {
    FileNoteHeader header;
    Reader::csptr entries;
    std::unique_ptr<ReaderArray<FileEntry>> entriesArray;
    Reader::csptr names;

public:
    class iterator {
        friend class FileEntries;
        const FileEntries &entries;
        void fetch();
        bool fetched = false;
        size_t nameoff = 0;
        std::pair<std::string, FileEntry> cur;
        ReaderArray<FileEntry>::iterator entriesIterator;
   public:
        iterator(const FileEntries &entries, ReaderArray<FileEntry>::iterator start);
        iterator &operator++();
        std::pair<std::string, FileEntry> operator *() { fetch(); return cur; }
        bool operator != (const iterator &rhs) const { return entriesIterator != rhs.entriesIterator; }
    };
    FileEntries(const Elf::Object &obj) {
        // find the Notes section.
        for (auto note : obj.notes()) {
            if (note.name() == "CORE" && note.type() == NT_FILE) {
                auto data = note.data();
                header = data->readObj<FileNoteHeader>(0);
                entries = data->view("FILE note entries", sizeof header, header.count * sizeof (FileEntry));
                names = data->view("FILE note names", sizeof header + header.count * sizeof (FileEntry));
                break;
            }
        }
        if (!entries)
           entries = std::make_shared<NullReader>();
        entriesArray = std::make_unique<ReaderArray<FileEntry>>(*entries);
    }
    iterator begin() const {
       return iterator(*this, entriesArray->begin());
    }
    iterator end() const {
       return iterator(*this, entriesArray->end());
    }
};


struct WaitStatus {
    int status;
    WaitStatus(int status) : status{status}{}
};

void gregset2core(Elf::CoreRegisters &core, const gregset_t greg);
}

std::ostream &operator << (std::ostream &os, pstack::Procman::WaitStatus ws);
std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::StackFrame, pstack::Procman::Process *> &jt);
std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::ThreadStack, pstack::Procman::Process *> &jt);
std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::FileEntry> &);

#endif
