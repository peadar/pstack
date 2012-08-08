#include <limits.h>
#include <iostream>
#include <link.h>
#include "procinfo.h"
#include "dwarf.h"

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
Process::addVDSOfromAuxV(const void *datap, size_t len)
{
    const Elf_auxv_t *aux = (const Elf_auxv_t *)datap;
    const Elf_auxv_t *eaux = aux + len / sizeof *aux;
    Elf_Addr hdr = 0;
    while (aux < eaux)
        if (aux->a_type == AT_SYSINFO_EHDR) {
            hdr = aux->a_un.a_val;
            vdso = new char[getpagesize()];
            readObj(hdr, vdso, getpagesize());
            MemReader *r = new MemReader(vdso, getpagesize());
            readers.push_back(r);
            addElfObject(new ElfObject(*r), hdr);
            return;
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
    obj->base = (Elf_Addr)-1;

    for (auto hdr : obj->programHeaders)
        if (hdr->p_type == PT_LOAD && hdr->p_vaddr < obj->base)
            obj->base = hdr->p_vaddr;
    objectList.push_back(obj);
    obj->dwarf = new DwarfInfo(obj);

    fprintf(stderr, "object %s loaded at address %p, base=%p\n", "XXX", (void *)obj->load, (void *)obj->base);
    auto di = obj->dwarf;
    fprintf(stderr, "unwind info: %s\n",
        di->ehFrame ? di->debugFrame ? "BOTH" : "EH" : di->debugFrame ? "DEBUG" : "NONE");

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
            std::clog << "warning: can't load text at " << (void *)mapAddr << "\n";
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
