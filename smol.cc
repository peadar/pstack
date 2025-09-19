#include "libpstack/proc.h"
#include "libpstack/arch.h"
#include <unistd.h>

extern "C" {
int foobar() {
    return 42;
}
}

int
main()
{
    extern int verbose;
    verbose = 0;
    PstackOptions options;
    Dwarf::ImageCache cache;
    getppid();
    std::shared_ptr<Process> p = std::make_shared<SelfProcess>(nullptr, options, cache);
    p->load();
    getppid();

    pstack::ProcessLocation li(*p, Elf::Addr(foobar));

    auto [ lib, addr, sym ]  = p->resolveSymbolDetail("foobar", true);
    std::cout << "found foobar in " << *lib->io << "@" << addr << ", value=" << sym.st_value << ", size=" << sym.st_size << std::endl;
    std::cout << "match? " << (Elf::Addr(foobar) == addr + sym.st_value) << std::endl;

    return foobar();
}
