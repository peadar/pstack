#ifndef libpstack_proc_h
#define libpstack_proc_h
#include <elf.h>
#include <memory.h>
extern "C" {
// Some thread_db headers are not safe to include unwrapped in extern "C"
#include <thread_db.h>
}

#include <map>
#include <set>
#include <sstream>
#include <functional>
#include <bitset>
#include <optional>
#include <ucontext.h> // for gregset_t

#include "libpstack/ps_callback.h"
#include "libpstack/dwarf.h"

struct ps_prochandle {};

struct PstackOptions {
   bool nosrc = false;
   bool doargs = false;
   bool dolocals = false;
   bool nothreaddb = false;
   int maxdepth = std::numeric_limits<int>::max();
   std::ostream *output = &std::cout;
};

namespace pstack::Procman {

class Process;

class StackFrame;
class ExpressionStack : public std::stack<Elf::Addr> {
public:
    bool isReg;
    int inReg;
    ExpressionStack(): isReg(false) {}
    Elf::Addr poptop() { Elf::Addr tos = top(); pop(); return tos; }
    Elf::Addr eval(const Process &, Dwarf::DWARFReader &r, const StackFrame*, Elf::Addr);
    Elf::Addr eval(const Process &, const Dwarf::DIE::Attribute &, const StackFrame*, Elf::Addr);
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
    const Dwarf::CFI *cfi() const;
    CodeLocation();
    CodeLocation(Dwarf::Info::sptr, const Elf::Phdr *, Elf::Addr location);

};

// This is a CodeLocation, but relocated for a process address.
struct ProcessLocation {
    Elf::Addr elfReloc;

    // XXX: can cache these in Dwarf::Info
    std::shared_ptr<CodeLocation> codeloc;

    void set(const Process &proc, Elf::Addr address);
    ProcessLocation(const Process &proc, Elf::Addr address_);
    Elf::Addr address() const { return elfReloc + codeloc->location_; }
    // these are proxies or the CodeLocation, adjusted by the elfReloc value.
    bool valid() const  { return codeloc != nullptr; }
    const Dwarf::DIE &die() const;
    const Dwarf::CIE *cie() const;
    const Dwarf::FDE *fde() const;
    const Dwarf::CFI *cfi() const;
    const Elf::MaybeNamedSymbol symbol() const;
    std::vector<std::pair<std::string, int>> source() const;
    Elf::Object::sptr elf() { return codeloc ? codeloc->dwarf_->elf : nullptr; }
    Dwarf::Info::sptr dwarf() { return codeloc ? codeloc->dwarf_ : nullptr; }
};

class StackFrame {
public:
    Elf::Addr rawIP() const;
    ProcessLocation scopeIP(const Process &) const;
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
    void getFrameBase(const Process &, intmax_t, ExpressionStack *) const;
};

struct ThreadStack {
    td_thrinfo_t info;
    std::vector<StackFrame> stack;
    ThreadStack() {
        memset(&info, 0, sizeof info);
    }
    void unwind(Process &, Elf::CoreRegisters &regs, unsigned maxFrames);
};

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
   off_t offset;
   DevNode backing;

   enum class Flags { read,write,exec,priv,count, shared };
   std::set<Flags> permissions;
};

class Process : public ps_prochandle {
    Elf::Addr entry;
    Elf::Addr interpBase;
    void loadSharedObjects(Elf::Addr);
public:
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
    PstackOptions options;
    static std::vector<AddressRange> procAddressSpace(const std::string &fn); //  utility to parse contents of /proc/pid/maps

public:
    Elf::Addr sysent; // for AT_SYSINFO
    std::map<pid_t, Lwp> lwps;
    Dwarf::ImageCache &imageCache;
    std::map<Elf::Addr, Elf::Object::sptr> objects;
    virtual Reader::csptr getAUXV() const = 0;
    void processAUXV(const Reader &);
    Reader::sptr io;

    virtual bool getRegs(lwpid_t pid, Elf::CoreRegisters *reg) = 0;
    void addElfObject(Elf::Object::sptr obj, Elf::Addr load);
    // Find the the object (and its load address) and segment containing a given address
    std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *> findSegment(Elf::Addr addr) const;
    Dwarf::Info::sptr getDwarf(Elf::Object::sptr) const;
    Process(Elf::Object::sptr exec, Reader::sptr memory, const PstackOptions &prl, Dwarf::ImageCache &cache);
    virtual void stop(pid_t lwpid) = 0;
    virtual void stopProcess() = 0;
    virtual void resumeProcess() = 0;
    virtual void resume(pid_t lwpid) = 0;
    std::ostream &dumpStackText(std::ostream &, const ThreadStack &, const PstackOptions &) const;
    std::ostream &dumpFrameText(std::ostream &, const PrintableFrame &, const StackFrame &) const;
    std::ostream &dumpStackJSON(std::ostream &, const ThreadStack &) const;
    template <typename T> void listThreads(const T &);


    // find address of named symbol in the process.
    Elf::Addr resolveSymbol(const char *symbolName, bool includeDebug,
          std::function<bool(Elf::Addr, const Elf::Object::sptr &)> matcher = [](Elf::Addr, const Elf::Object::sptr &) { return true; }) const;

    // find symbol data of named symbol in the process.
    // like resolveSymbol, but return the library and that library's load address as well as the address in the process.
    std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Sym>
    resolveSymbolDetail(const char *name, bool includeDebug,
                        std::function<bool(Elf::Addr, const Elf::Object::sptr&)> match =
                           [](Elf::Addr, const Elf::Object::sptr &) { return true; }) const;
    virtual std::list<ThreadStack> getStacks(const PstackOptions &, unsigned maxFrames);
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
public:
    // attach to existing process.
    LiveProcess(Elf::Object::sptr &, pid_t, const PstackOptions &, Dwarf::ImageCache &, bool alreadyStopped=false);

    virtual bool getRegs(lwpid_t pid, Elf::CoreRegisters *reg) override;
    virtual void stop(pid_t) override;
    virtual void resume(pid_t) override;
    void stopProcess() override;
    void resumeProcess() override;
    virtual Reader::csptr getAUXV() const override;
    void findLWPs();
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

    virtual bool getRegs(lwpid_t pid, Elf::CoreRegisters *reg) override;
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
public:
    Elf::Object::sptr coreImage;
    CoreProcess(Elf::Object::sptr exec, Elf::Object::sptr core, const PstackOptions &, Dwarf::ImageCache &);
    virtual bool getRegs(lwpid_t pid, Elf::CoreRegisters *reg) override;
    virtual void stop(lwpid_t) override;
    virtual void resume(lwpid_t) override;
    void stopProcess() override;
    void resumeProcess()  override { }
    virtual Reader::csptr getAUXV() const override;
    virtual pid_t getPID() const override;
protected:
    std::vector<prstatus_t> tasks;
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
class LogProcess final : public Process {
   const std::vector<std::string> &logs;
   std::list<ThreadStack> stacks;
public:
   LogProcess(Elf::Object::sptr exec, const std::vector<std::string> &logs, const PstackOptions &, Dwarf::ImageCache &);
   Reader::csptr getAUXV() const;
   bool getRegs(lwpid_t, Elf::CoreRegisters *);
   void resume(pid_t);
   void resumeProcess();
   void stop(lwpid_t);
   void stopProcess();
   std::vector<AddressRange> addressSpace() const;
   pid_t getPID() const;
   bool loadSharedObjectsFromFileNote();
   virtual std::list<ThreadStack> getStacks(const PstackOptions &, unsigned maxFrames);
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
        const FileEntries &entries;
        void fetch();
        size_t nameoff = 0;
        std::pair<std::string, FileEntry> cur;
        ReaderArray<FileEntry>::iterator entriesIterator;
    public:
        iterator(const FileEntries &entries, ReaderArray<FileEntry>::iterator start);
        iterator &operator++();
        std::pair<std::string, FileEntry> operator *() { return cur; }
        bool operator != (const iterator &rhs) const { return entriesIterator != rhs.entriesIterator; }
    };
    FileEntries(const Elf::Object &obj) {
        // find the Notes section.
        for (auto note : obj.notes()) {
            if (note.name() == "CORE" && note.type() == NT_FILE) {
                auto data = note.data();
                header = data->readObj<FileNoteHeader>(0);
                entries = data->view("FILE note entries", sizeof header, header.count * sizeof (FileEntry));
                entriesArray = std::make_unique<ReaderArray<FileEntry>>(*entries);
                names = data->view("FILE note names", sizeof header + header.count * sizeof (FileEntry));
                break;
            }
        }
    }
    iterator begin() const { return iterator(*this, entriesArray->begin()); }
    iterator end() const { return iterator(*this, entriesArray->end()); }
};


struct WaitStatus {
   int status;
   WaitStatus(int status) : status{status}{}
};

void gregset2core(Elf::CoreRegisters &core, const gregset_t greg);
}

std::ostream &operator << (std::ostream &os, pstack::Procman::WaitStatus ws);
std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::StackFrame, const pstack::Procman::Process *> &jt);
std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::ThreadStack, const pstack::Procman::Process *> &jt);
std::ostream &operator << (std::ostream &os, const JSON<pstack::Procman::FileEntry> &);

#endif
