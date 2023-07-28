#include <libpstack/proc.h>
#include <libpstack/archreg.h>
#include <unistd.h>

extern "C" {
int foobar() {
    return 42;
}
}

int

main()
{
    /*
    extern int verbose;
    verbose = 0;
    PstackOptions options;
    Dwarf::ImageCache cache;
    getppid();
    std::shared_ptr<Process> p = std::make_shared<SelfProcess>(nullptr, options, cache);
    p->load();
    getppid();

    Dwarf::StackFrame sf(Dwarf::UnwindMechanism::MACHINEREGS);
    sf.setReg(IPREG, uintptr_t(foobar));
    sf.findObjectCode(*p);

    std::cout << json(sf, p.get()) << std::endl;

    auto [ lib, addr, sym ]  = p->resolveSymbolDetail("foobar", true);
    std::cout << "found foobar in " << *lib->io << "@" << addr << ", value=" << sym.st_value << ", size=" << sym.st_size << std::endl;
    
    return foobar();
    */
}
