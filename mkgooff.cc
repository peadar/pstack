#include "libpstack/context.h"
#include "libpstack/go.h"

#include <fstream>
#include <iostream>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        std::cerr << "usage: pstack-mkgooff <go-executable>\n";
        return 2;
    }

    try {
        pstack::Context context;
        auto elf = context.findImage(argv[1]);
        if (!elf)
            throw pstack::Exception() << argv[1] << " is not an ELF image";
        auto goVersion = pstack::Go::version(*elf);
        auto dwarf = context.findDwarf(elf);
        auto offsets = pstack::Go::runtimeOffsets(
                dwarf, goVersion, elf->getMachineName(), sizeof(pstack::Elf::Addr));

        const auto fileName = pstack::Go::offsetFileName(goVersion, elf->getMachineName());
        std::ofstream out(fileName);
        if (!out)
            throw pstack::Exception() << "cannot create " << fileName;

        {
            pstack::JObject json(out);
            json.field("version", offsets.version)
                .field("machine", offsets.machine)
                .field("pointer_size", offsets.pointerSize)
                .field("allgs_data", offsets.allgsData)
                .field("allgs_length", offsets.allgsLength)
                .field("allgs_stride", offsets.allgsStride)
                .field("g_size", offsets.gSize)
                .field("g_sched", offsets.gSched)
                .field("g_goid", offsets.gGoid)
                .field("gobuf_sp", offsets.gobufSp)
                .field("gobuf_pc", offsets.gobufPc);
            if (offsets.gobufBp)
                json.field("gobuf_bp", *offsets.gobufBp);
            if (offsets.gobufG)
                json.field("gobuf_g", *offsets.gobufG);
            if (offsets.gobufCtxt)
                json.field("gobuf_ctxt", *offsets.gobufCtxt);
            if (offsets.gobufLr)
                json.field("gobuf_lr", *offsets.gobufLr);
        }
        out << "\n";
        std::clog << "wrote " << fileName << "\n";
    }
    catch (const std::exception &ex) {
        std::cerr << "pstack-mkgooff: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
