#include <limits.h>
#include <iostream>
#include <link.h>
#include "procinfo.h"
#include "dwarf.h"

static std::string auxv_name(Elf_Word val)
{
#define AUXV(n) case n : return #n;
    switch (val) {
        AUXV(AT_NULL)
        AUXV(AT_IGNORE)
        AUXV(AT_EXECFD)
        AUXV(AT_PHDR)
        AUXV(AT_PHENT)
        AUXV(AT_PHNUM)
        AUXV(AT_PAGESZ)
        AUXV(AT_BASE)
        AUXV(AT_FLAGS)
        AUXV(AT_ENTRY)
        AUXV(AT_NOTELF)
        AUXV(AT_UID)
        AUXV(AT_EUID)
        AUXV(AT_GID)
        AUXV(AT_EGID)
        AUXV(AT_CLKTCK)
        AUXV(AT_PLATFORM)
        AUXV(AT_HWCAP)
        AUXV(AT_FPUCW)
        AUXV(AT_DCACHEBSIZE)
        AUXV(AT_ICACHEBSIZE)
        AUXV(AT_UCACHEBSIZE)
        AUXV(AT_IGNOREPPC)
        AUXV(AT_SECURE)
        AUXV(AT_BASE_PLATFORM)
        AUXV(AT_RANDOM)
        AUXV(AT_EXECFN)
        AUXV(AT_SYSINFO)
        AUXV(AT_SYSINFO_EHDR)
        AUXV(AT_L1I_CACHESHAPE)
        AUXV(AT_L1D_CACHESHAPE)
        AUXV(AT_L2_CACHESHAPE)
        AUXV(AT_L3_CACHESHAPE)
        default: return "unknown";
    }
}
#undef AUXV

template <typename T> static void
delall(T &container)
{
    for (auto i : container)
        delete i;
}

Process::Process(Reader &exeData)
    : execImage(new ElfObject(exeData))
{
    abiPrefix = execImage->getABIPrefix();
    addElfObject(execImage, 0);
    execImage->load = execImage->base; // An executable is loaded at its own base address
}

void
Process::load()
{
    td_err_e the;
    /* Attach any dynamically-linked libraries */
    loadSharedObjects();
    the = td_ta_new(this, &agent);
    if (the != TD_OK)
        agent = 0;
}

void
Process::processAUXV(const void *datap, size_t len)
{
    const Elf_auxv_t *aux = (const Elf_auxv_t *)datap;
    const Elf_auxv_t *eaux = aux + len / sizeof *aux;
    for (; aux < eaux; aux += sizeof *aux) {
        Elf_Addr hdr = aux->a_un.a_val;
        std::cerr << "auxv: " << auxv_name(aux->a_type) << "= " << (void *)hdr << "\n";
        switch (aux->a_type) {
            case AT_SYSINFO_EHDR: {
                vdso = new char[getpagesize()];
                readObj(hdr, vdso, getpagesize());
                MemReader *r = new MemReader(vdso, getpagesize());
                readers.push_back(r);
                addElfObject(new ElfObject(*r), hdr);
                break;
            }

            case AT_EXECFN:
                std::ostringstream os;
                for (;;) {
                    char c;
                    readObj(hdr++, &c, 1);
                    if (c == 0)
                        break;
                    os << c;
                }
                std::cerr << "filename: " << os.str() << "\n";
                break;
        }
    }
}

void
Process::dumpStack(FILE *file, int indent, const ThreadStack &thread, bool verbose)
{
    struct ElfObject *obj;
    int lineNo;
    Elf_Sym sym;
    std::string fileName;
    const char *padding;
    std::string symName;

    padding = pad(indent);
    for (auto frame : thread.stack) {
        symName = fileName = "????????";
        Elf_Addr objIp;
        obj = findObject(frame->ip);

        if (obj != 0) {
            fileName = obj->io.describe();
            obj->findSymbolByAddress(obj->addrProc2Obj(frame->ip), STT_FUNC, sym, symName);
            objIp = obj->addrProc2Obj(frame->ip);
        } else {
            objIp = 0;
        }
        fprintf(file, "%s%p ", padding - 1, (void *)(intptr_t)frame->ip);

        if (verbose) { /* Show ebp for verbose */
#ifdef i386
            fprintf(file, "%p ", (void *)frame->bp);
#endif
            fprintf(file, "%s ", frame->unwindBy);
        }

        fprintf(file, "%s (", symName.c_str());
        if (frame->args.size()) {
            auto i = frame->args.begin();
            for (; i != frame->args.end(); ++i)
                fprintf(file, "%x, ", *i);
            fprintf(file, "%x", *i);
        }
        fprintf(file, ")");
        if (obj != 0) {
            printf(" + %p", (void *)((intptr_t)objIp - sym.st_value));
            printf(" in %s", fileName.c_str());
            if (obj->dwarf && obj->dwarf->sourceFromAddr(objIp - 1, fileName, lineNo))
                printf(" (source %s:%d)", fileName.c_str(), lineNo);
        }
        printf("\n");
    }
    fprintf(file, "\n");
}

void
Process::addElfObject(struct ElfObject *obj, Elf_Addr load)
{
    obj->load = load;
    obj->base = (Elf_Addr)0;

    for (auto hdr : obj->programHeaders)
        if (hdr->p_type == PT_LOAD && (Elf_Off)hdr->p_vaddr <= obj->base)
            obj->base = hdr->p_vaddr;
    objectList.push_back(obj);
    obj->dwarf = new DwarfInfo(obj);

    std::cerr << "object " << obj->io.describe() << " loaded at address " << std::hex << obj->load << ", base=" << obj->base;
    auto di = obj->dwarf;
    std::cerr << ", unwind info:  " << (di->ehFrame ? di->debugFrame ? "BOTH" : "EH" : di->debugFrame ? "DEBUG" : "NONE") << "\n";

}
/*
 * Grovel through the rtld's internals to find any shared libraries.
 */
void
Process::loadSharedObjects()
{
    int maxpath;
    char prefixedPath[PATH_MAX + 1], *path;

    /* Does this process look like it has shared libraries loaded? */
    Elf_Addr r_debug_addr = findRDebugAddr();
    if (r_debug_addr == 0 || r_debug_addr == (Elf_Addr)-1)
        return;

    struct r_debug rDebug;
    readObj(r_debug_addr, &rDebug);
    if (abiPrefix != "") {
        path = prefixedPath + snprintf(prefixedPath, sizeof(prefixedPath), "%s", abiPrefix.c_str());
        maxpath = PATH_MAX - strlen(abiPrefix.c_str());
    } else {
        path = prefixedPath;
        maxpath = PATH_MAX;
    }

    /* Iterate over the r_debug structure's entries, loading libraries */
    struct link_map map;
    for (Elf_Addr mapAddr = (Elf_Addr)rDebug.r_map; mapAddr; mapAddr = (Elf_Addr)map.l_next) {
        readObj(mapAddr, &map);

        /* Read the path to the file */
        if (map.l_name == 0)
            continue;
        try {
            readObj((off_t)map.l_name, path, maxpath);
            if (abiPrefix != "" && access(prefixedPath, R_OK) == 0)
                path = prefixedPath;
            FileReader *f = new FileReader(path);
            readers.push_back(f);
            Elf_Addr lAddr = (Elf_Addr)map.l_addr;
            addElfObject(new ElfObject(*f), lAddr);
        }
        catch (...) {
            std::clog << "warning: can't load text at " << (void *)mapAddr << "/" << (void *)mapAddr << "\n";
            continue;
        }

    }
}

Elf_Addr
Process::findRDebugAddr()
{
    // Find DT_DEBUG in the process's dynamic section.
    if (execImage->dynamic == 0)
        return 0;

    for (Elf_Addr dynOff = 0; dynOff < execImage->dynamic->p_filesz; dynOff += sizeof(Elf_Dyn)) {
        Elf_Dyn dyn;
        execImage->io.readObj(execImage->dynamic->p_offset + dynOff, &dyn);
        if (dyn.d_tag == DT_DEBUG) {
            readObj(execImage->dynamic->p_vaddr + dynOff, &dyn);
            return dyn.d_un.d_ptr;
        }
    }
    return 0;
}


ElfObject *
Process::findObject(Elf_Addr addr) const
{
    for (auto obj : objectList) {
        Elf_Addr va = obj->addrProc2Obj(addr);
        for (auto phdr : obj->programHeaders)
            if (va >= phdr->p_vaddr && va < phdr->p_vaddr + phdr->p_memsz)
                return obj;
    }
    return 0;
}

Elf_Addr
Process::findNamedSymbol(const char *objectName, const char *symbolName) const
{
    for (auto obj : objectList) {
        if (objectName != 0) {
            auto objname = obj->io.describe();
            auto p = objname.rfind('/');
            if (p != std::string::npos)
                objname = objname.substr(p + 1, std::string::npos);
            if (objname != std::string(objectName))
                continue;
        }
        Elf_Sym sym;
        if (obj->findSymbolByName(symbolName, sym))
            return obj->addrObj2Proc(sym.st_value);
        if (objectName)
            throw 999;
    }
    throw 999;
}

Process::~Process()
{
    delall(objectList);
    delete[] vdso;
}
