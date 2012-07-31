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
    pid_t pid;
    std::list<ElfObject *> objectList;
    std::list<Thread *> threadList;
    ElfObject *execImage;
    ElfObject *coreImage;
    std::string abiPrefix;
    PageCache pageCache;
    char *vdso;
    void openLive(pid_t pid);
    void closeLive();
    void loadSharedObjects();
    Elf_Addr findRDebugAddr();
public:
    int getRegs(lwpid_t pid, CoreRegisters *reg);
    void addElfObject(struct ElfObject *obj, Elf_Addr load);
    ElfObject *findObject(Elf_Addr addr);
    ps_prochandle(pid_t pid, const char *exeName, const char *coreFile);
    size_t readMem(char *ptr, Elf_Addr remoteAddr, size_t count);
    void addThread(thread_t id, const CoreRegisters &, lwpid_t lwp);
    void dumpStacks(FILE *f, int indent);
    ~ps_prochandle();
};
