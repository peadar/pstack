#include <iostream>
#include <stddef.h>
#include <libpstack/dwarf.h>
#include <libpstack/proc.h>
#include <python2.7/Python.h>
#include <python2.7/frameobject.h>

Elf_Addr
doPyThread(Process &proc, std::ostream &os, Elf_Addr ptr)
{
    PyThreadState state;
    proc.io->readObj(ptr, &state);
    PyFrameObject frame;
    os << "\tthread " << ptr << std::endl;
    for (Elf_Addr framePtr = reinterpret_cast<Elf_Addr>(state.frame);
            framePtr != 0;
            framePtr = reinterpret_cast<Elf_Addr>(frame.f_back)) {
        proc.io->readObj(framePtr, &frame);
        PyCodeObject code;
        PyStringObject function;
        proc.io->readObj(reinterpret_cast<Elf_Addr>(frame.f_code), &code);
        auto func = proc.io->readString(reinterpret_cast<Elf_Addr>(code.co_name) + offsetof(PyStringObject, ob_sval));
        auto file = proc.io->readString(reinterpret_cast<Elf_Addr>(code.co_filename) + offsetof(PyStringObject, ob_sval));
        os << "\t\t" << func << " in " << file << ":" << frame.f_lineno << "\n";
    }
    return reinterpret_cast<Elf_Addr>(state.next);
}

Elf32_Addr
doPyInterp(Process &proc, std::ostream &os, Elf_Addr ptr)
{
    PyInterpreterState state;
    proc.io->readObj(ptr, &state);
    os << "interpreter " << ptr << std::endl;
    for (Elf_Addr tsp = reinterpret_cast<Elf_Addr>(state.tstate_head); tsp; ) {
        tsp = doPyThread(proc, os, tsp);
    }
    return reinterpret_cast<Elf_Addr>(state.next);
}
    /*
    PyThreadState *tstate = PyThreadState_GET();
    if (nullptr != tstate && nullptr != tstate->frame) {
	PyFrameObject *frame = tstate->frame;

	printf("Python stack trace:\n");
	while (nullptr != frame) {
	    // int line = frame->f_lineno;
	    int line = PyCode_Addr2Line(frame->f_code, frame->f_lasti);
	    const char *filename = PyString_AsString(frame->f_code->co_filename);
	    const char *funcname = PyString_AsString(frame->f_code->co_name);
	    printf("    %s(%d): %s\n", filename, line, funcname);
	    frame = frame->f_back;
	}
    }
*/

std::ostream &
pythonStack(Process &proc, std::ostream &os, const PstackOptions &)
{
    // Find the python library.
    for (auto &o : proc.objects) {
        std::string module = stringify(*o.object->io);
        if (module.find("python") != std::string::npos) {
            auto dwarf = proc.imageCache.getDwarf(ElfObject::getDebug(o.object));
            if (dwarf) {
                std::clog << "searching  " << module << std::endl;
                for (auto u : dwarf->getUnits()) {
                    for (const DwarfEntry *compile : u->entries) {
                        if (compile->type->tag == DW_TAG_compile_unit) {
                            for (const DwarfEntry *var : compile->children) {
                                if (var->type->tag == DW_TAG_variable && var->name() == "interp_head") {
                                    DwarfExpressionStack evalStack;
                                    auto addr = evalStack.eval(proc, var->attrForName(DW_AT_location), 0, o.reloc);
                                    Elf_Addr ptr;
                                    for (proc.io->readObj(addr, &ptr); ptr; ) {
                                        ptr = doPyInterp(proc, os, ptr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return os;
}


