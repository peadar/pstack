#include "libpstack/proc.h"
#include "libpstack/imagecache.h"
#include "libpstack/global.h"
#include "libpstack/archreg.h"
#include <unistd.h>
#include <cassert>

extern "C" {
int foobar() {
    return 42;
}
}

int
main()
{
    pstack::verbose = 0;
    PstackOptions options;
    pstack::ImageCache cache;
    getppid();
    std::shared_ptr<pstack::Procman::Process> p = std::make_shared<pstack::Procman::SelfProcess>(nullptr, options, cache);
    p->load();

    pstack::Procman::ProcessLocation li(*p, pstack::Elf::Addr(foobar));

    auto [ lib, addr, sym ]  = p->resolveSymbolDetail("foobar", true);

    std::cout << "found foobar in " << *lib->io << "@" << addr << ", value=" << sym.st_value << ", size=" << sym.st_size << std::endl;
    assert(pstack::Elf::Addr(foobar) == addr + sym.st_value);
    return 0;
}
