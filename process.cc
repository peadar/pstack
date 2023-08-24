#include <features.h>

#include "libpstack/archreg.h"
#include "libpstack/dwarf.h"
#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"
#include "libpstack/global.h"
#include "libpstack/stringify.h"
#include "libpstack/ioflag.h"

#include <link.h>
#include <unistd.h>

#include <cassert>
#include <climits>

#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <signal.h>



/*
 * convert a gregset_t to an Elf::CoreRegs
 */
#ifndef __aarch64__
void
gregset2core(Elf::CoreRegisters &core, const gregset_t greg) {
#if defined(__i386__)
    core.edi = greg[REG_EDI];
    core.esi = greg[REG_ESI];
    core.ebp = greg[REG_EBP];
    core.esp = greg[REG_ESP];
    core.ebx = greg[REG_EBX];
    core.edx = greg[REG_EDX];
    core.ecx = greg[REG_ECX];
    core.eax = greg[REG_EAX];
    core.eip = greg[REG_EIP];
#elif defined(__amd64__)
    core.r8 = greg[REG_R8];
    core.r9 = greg[REG_R9];
    core.r10 = greg[REG_R10];
    core.r11 = greg[REG_R11];
    core.r12 = greg[REG_R12];
    core.r13 = greg[REG_R13];
    core.r14 = greg[REG_R14];
    core.r15 = greg[REG_R15];
    core.rdi = greg[REG_RDI];
    core.rsi = greg[REG_RSI];
    core.rbp = greg[REG_RBP];
    core.rbx = greg[REG_RBX];
    core.rdx = greg[REG_RDX];
    core.rax = greg[REG_RAX];
    core.rcx = greg[REG_RCX];
    core.rsp = greg[REG_RSP];
    core.rip = greg[REG_RIP];
#elif defined(__arm__)
    // ARM has unfied types for NT_PRSTATUS and ucontext, and the offsets are
    // actually the DWARF register numbers, too.
    for (int i = 0; i < ELF_NGREG)
        core.regs[i] = greg[i];
#endif
}
#endif


Process::Process(Elf::Object::sptr exec, Reader::sptr memory,
                  const PstackOptions &options, Dwarf::ImageCache &cache)
    : entry(0)
    , interpBase(0)
    , vdsoBase(0)
    , agent(nullptr)
    , execImage(std::move(exec))
    , options(options)
    , sysent(0)
    , imageCache(cache)
    , io(std::move(memory))
{
    if (execImage)
        entry = execImage->getHeader().e_entry;
}

void
Process::load()
{
    /*
     * Attach the executable and any shared libs.
     * The process is still running here, but unless its actively loading or
     * unload a shared library, this relatively safe, and saves us a lot of
     * work while the process is stopped.
     */

    StopProcess here(this);
    auto auxv = getAUXV();
    if (auxv)
        processAUXV(*auxv);

    if (!execImage)
        throw (Exception() << "no executable image located for process");

    try {
        Elf::Addr r_debug_addr = findRDebugAddr();
        bool isStatic = r_debug_addr == 0 || r_debug_addr == Elf::Addr(-1);

        if (isStatic)
            addElfObject(execImage, 0);
        else
            loadSharedObjects(r_debug_addr);
    }
    catch (const Exception &) {
        // We were unable to read the link map.
        // The primary cause is that the core file is truncated.
        // Go do the Hail Mary version.
        if (loadSharedObjectsFromFileNote())
            return;
        throw;
    }

    if (!options.nothreaddb) {
        td_err_e the;
        the = td_ta_new(this, &agent);
        if (the != TD_OK) {
            agent = nullptr;
            if (verbose > 0 && the != TD_NOLIBTHREAD)
                *debug << "failed to load thread agent: " << the << std::endl;
        }
    }

}

Dwarf::Info::sptr
Process::getDwarf(Elf::Object::sptr elf) const
{
    return imageCache.getDwarf(elf);
}


const char *
auxtype2str(int auxtype) {
#define AUX_TYPE(t, v) if (auxtype == t) return #t;
#include "libpstack/elf/aux.h"
   return "unknown type";
#undef AUX_TYPE
}

void
Process::processAUXV(const Reader &auxio)
{
    for (size_t i = 0;; i++) {
        Elf::auxv_t aux;
        try {
            auxio.readObj(i * sizeof aux, &aux);
        }
        catch (const Exception &ex) {
            break;
        }

        Elf::Addr hdr = aux.a_un.a_val;
        switch (aux.a_type) {
            case AT_ENTRY: {
                if (verbose > 2)
                   *debug << "auxv: AT_ENTRY=" << hdr << std::endl;
                // this provides a reference for relocating the executable when
                // compared to the entrypoint there.
                entry = hdr;
                break;
            }
            case AT_SYSINFO: {
                if (verbose > 2)
                   *debug << "auxv:AT_SYSINFO=" << hdr << std::endl;
                sysent = hdr;
                break;
            }
            case AT_SYSINFO_EHDR: {
                try {
                    auto elf = std::make_shared<Elf::Object>(imageCache, io->view("(vdso image)", hdr, 65536));
                    vdsoBase = hdr;
                    addElfObject(elf, hdr);
                    vdsoImage = elf;
                    if (verbose >= 2) {
                        *debug << "auxv: VDSO " << *elf->io
                           << " loaded at " << std::hex << hdr << std::dec << "\n";
                    }

                }
                catch (const std::exception &ex) {
                    std::clog << "auxv: warning: failed to load DSO: " << ex.what() << "\n";
                }
                break;
            }
            case AT_BASE:
                if (verbose > 2)
                   *debug << "auxv: AT_BASE=" << hdr << std::endl;
                interpBase = hdr;
                break;
#ifdef AT_EXECFN
            case AT_EXECFN: {
                if (verbose > 2)
                   *debug << "auxv: AT_EXECFN=" << hdr << std::endl;
                try {
                    auto exeName = io->readString(hdr);
                    if (verbose >= 2)
                        *debug << "filename from auxv: " << exeName << "\n";
                    if (!execImage) {
                        execImage = imageCache.getImageForName(exeName);
                        if (entry == 0)
                           entry = execImage->getHeader().e_entry;
                    }
                }
                catch (const Exception &ex) {
                    *debug << "failed to read AT_EXECFN: " << ex.what() << std::endl;
                }

                break;
            }
#endif
            default:
                if (verbose > 2)
                   *debug << "auxv: " << auxtype2str( aux.a_type) << ": " << hdr << std::endl;
        }
    }
}

template <typename ctx>
std::ostream &
operator << (std::ostream &os, const JSON<td_thr_type_e, ctx> &jt)
{
    switch (jt.object) {
        case TD_THR_ANY_TYPE: return os << json("TD_THR_ANY_TYPE");
        case TD_THR_USER: return os << json("TD_THR_USER");
        case TD_THR_SYSTEM: return os << json("TD_THR_SYSTEM");
        default: return os << json("unknown type");
    }
}

static bool
dieName(std::ostream &os, const Dwarf::DIE &die, bool first=true) {
    // use the specification or abstract origin DIE instead of this if we have one.
    auto spec = die.attribute(Dwarf::DW_AT_specification);
    if (spec.valid())
        return dieName(os, Dwarf::DIE(spec), first);
    auto origin = die.attribute(Dwarf::DW_AT_abstract_origin);
    if (origin.valid())
        return dieName(os, Dwarf::DIE(origin), first);

    // Don't walk up past compile units.
    if (die.tag() == Dwarf::DW_TAG_compile_unit || die.tag() == Dwarf::DW_TAG_partial_unit)
        return false;

    auto parent = die.getParentOffset();
    assert(parent != 0); // because die would have been a unit or partial unit
    bool printedParent = dieName(os, die.getUnit()->offsetToDIE(Dwarf::DIE(), parent), false);

    auto tag = die.tag();
    if (first ||
            tag == Dwarf::DW_TAG_structure_type ||
            tag == Dwarf::DW_TAG_class_type ||
            tag == Dwarf::DW_TAG_namespace ) {
        if (printedParent)
            os << "::";
       os << die.name();
       return true;
    }
    return printedParent;
}

// Data useful for both JSON and text printed formats.
struct PrintableFrame {
    const Process &proc;
    int frameNumber;
    std::string dieName;
    const PstackOptions &options;
    Elf::Addr functionOffset;
    const Dwarf::StackFrame &frame;
    std::vector<Dwarf::DIE> inlined; // func + inlined.
    PrintableFrame(const Process &, const Dwarf::StackFrame &frame, int frameNo, const PstackOptions &options);
    PrintableFrame(const PrintableFrame &) = delete;
    PrintableFrame() = delete;
};

PrintableFrame::PrintableFrame(const Process &proc, const Dwarf::StackFrame &frame, int frameNo, const PstackOptions &options)
    : proc(proc)
    , frameNumber(frameNo)
    , options(options)
    , functionOffset(std::numeric_limits<Elf::Addr>::max())
    , frame(frame)
{
    auto location = frame.scopeIP(proc);

    if (location.elf() == nullptr)
        return;
    Elf::Addr objIp = location.address() - location.elfReloc;
    auto function = location.die();
    if (function) {
        std::ostringstream sos;
        ::dieName(sos, function);
        this->dieName = sos.str();
        auto lowpc = function.attribute(Dwarf::DW_AT_low_pc);
        if (lowpc.valid()) {
            functionOffset = objIp - uintmax_t(lowpc);
        } else {
            auto ranges = function.getRanges();
            if (ranges) {
                functionOffset = objIp - (*ranges)[0].first;
            } else {
                // no function start address - we'll try and find it
                // below in the ELF fallback code.
            }
        }
        while (function) {
            auto inl = function.findEntryForAddr(objIp, Dwarf::DW_TAG_inlined_subroutine);
            if (!inl)
                break;
            inlined.push_back(inl);
            function = std::move(inl);
        }
    }
    if (functionOffset == std::numeric_limits<Elf::Addr>::max()) {
        // If we have not worked out the start of the function, then we
        // either didn't find the DIE for the function, or it didn't have
        // enough info to find the first address.
        //
        // Fall back to using the ELF symbol instead.
        auto maybesym = location.symbol();
        if (maybesym)
            functionOffset = objIp - maybesym->first.st_value;
    }
}

std::ostream &
operator << (std::ostream &os, const JSON<std::pair<std::string, int>> &jt)
{
    return JObject(os)
        .field("file", jt.object.first)
        .field("line", jt.object.second);
}

std::ostream &
operator << (std::ostream &os, const JSON<std::pair<Elf::Sym, std::string>> &js)
{
    const auto &obj = js.object;
    return JObject(os)
        .field("st_name", obj.second)
        .field("st_value", obj.first.st_value)
        .field("st_size", obj.first.st_size)
        .field("st_info", int(obj.first.st_info))
        .field("st_other", int(obj.first.st_other))
        .field("st_shndx", obj.first.st_shndx);
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::ProcessLocation, const Process *> &)
{
    return os;
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::StackFrame, const Process *> &jt)
{
    auto &frame =jt.object;
    PstackOptions options;
    options.doargs = true;
    Dwarf::ProcessLocation location = frame.scopeIP(*jt.context);
    PrintableFrame pframe(*jt.context, frame, 0, options);

    JObject jo(os);
    jo
        .field("ip", frame.rawIP())
        .field("offset", pframe.functionOffset)
        .field("trampoline", frame.isSignalTrampoline)
        .field("die", pframe.dieName)
        .field("loadaddr", location.elfReloc)
        ;

    const auto &sym = location.symbol();
    if (sym)
        jo.field("symbol", *sym);
    else
        jo.field("symbol", JsonNull());

    jo.field("source", location.source());

    return jo;
}

std::ostream &
operator << (std::ostream &os, const JSON<ThreadStack, const Process *> &ts)
{
    return JObject(os)
        .field("ti_tid", ts.object.info.ti_tid)
        .field("ti_lid", ts.object.info.ti_lid)
        .field("ti_type", ts.object.info.ti_type)
        .field("ti_pri", ts.object.info.ti_pri)
        .field("ti_stack", ts.object.stack, ts.context);
}

struct ArgPrint {
    const Process &p;
    const PrintableFrame &pframe;
    ArgPrint(const Process &p_, const PrintableFrame &pframe_)
        : p(p_), pframe(pframe_) {}
};

struct RemoteValue {
    const Process &p;
    const Elf::Addr addr;
    const Dwarf::DIE type;
    RemoteValue(const Process &p_, Elf::Addr addr_, Dwarf::DIE type_)
        : p(p_)
        , addr(addr_)
        , type(type_)
    {}
};

struct ProcPtr {
    const Process &proc;
    const Dwarf::DIE &type;
    Elf::Addr addr;
    ProcPtr(const Process &proc_, const Dwarf::DIE &type_, Elf::Addr addr_)
        : proc(proc_)
        , type(type_)
        , addr(addr_)
    {}
};

std::ostream &
operator << (std::ostream &os, const ProcPtr &pp) {
    using namespace Dwarf;
    DIE base;
    for (base = DIE(pp.type.attribute(DW_AT_type)); 
        base && base.tag() == DW_TAG_const_type;
        base = DIE(base.attribute(DW_AT_type))) 
        ;

    if (base && base.name() == "char") {
       std::string s = pp.proc.io->readString(pp.addr);
       os << "\"" << s << "\"";
    } else {
       os << pp.addr << "(" << (void *)pp.addr << ")";
    }
    return os;
}

std::ostream &
operator << (std::ostream &os, const RemoteValue &rv)
{
    using namespace Dwarf;
    if (rv.addr == 0)
       return os << "(null)";
    auto type = rv.type;
    while (type.tag() == DW_TAG_typedef || type.tag() == DW_TAG_const_type)
       type = DIE(type.attribute(DW_AT_type));


    uintmax_t size;
    std::vector<char> buf;
    auto sizeAttr = type.attribute(DW_AT_byte_size);
    if (sizeAttr.valid()) {
        size = uintmax_t(sizeAttr);
        buf.resize(size);
        auto rc = rv.p.io->read(rv.addr, size, &buf[0]);
        if (rc != size) {
            return os << "<error reading " << size << " bytes from " << rv.addr
               << ", got " << rc << ">";
        }
    } else {
       size = 0;
    }

    IOFlagSave _(os);
    switch (type.tag()) {
        case DW_TAG_base_type: {
            if (size == 0) {
                os << "unrepresentable(1)";
            }
            auto encoding = type.attribute(DW_AT_encoding);
            if (!encoding.valid())
                throw (Exception() << "no encoding specified for base type");

            union {
               int8_t *int8;
               int16_t *int16;
               int32_t *int32;
               int64_t *int64;
               void **voidp;
               char *cp;
            } u;
            u.cp = &buf[0];

            switch (uintmax_t(encoding)) {
                case DW_ATE_address:
                    os << *u.voidp;
                    break;
                case DW_ATE_boolean:
                    for (size_t i = 0;; ++i) {
                        if (i == size) {
                            os << "false";
                            break;
                        }
                        if (buf[i] != 0) {
                            os << "true";
                            break;
                        }
                    }
                    break;

                case DW_ATE_signed:
                case DW_ATE_signed_char:
                    switch (size) {
                        case sizeof (int8_t):
                            os << *u.int8;
                            break;
                        case sizeof (int16_t):
                            os << *u.int16;
                            break;
                        case sizeof (int32_t):
                            os << *u.int32;
                            break;
                        case sizeof (int64_t):
                            os << *u.int64;
                            break;
                    }
                    break;

                case DW_ATE_unsigned:
                case DW_ATE_unsigned_char:
                    switch (size) {
                        case sizeof (uint8_t):
                            os << *u.int8;
                            break;
                        case sizeof (uint16_t):
                            os << *u.int16;
                            break;
                        case sizeof (uint32_t):
                            os << *u.int32;
                            break;
                        case sizeof (uint64_t):
                            os << *u.int64;
                            break;
                        default:
                            abort();
                    }
                    break;

                default:
                    abort();
            }
            break;
        }
        case DW_TAG_reference_type:
        case DW_TAG_pointer_type: {
            if (size == 0) {
               buf.resize(sizeof (void *));
               rv.p.io->read(rv.addr, sizeof (void **), &buf[0]);
            }
            os << ProcPtr(rv.p, type, *(Elf::Addr *)&buf[0]);
            break;
        }
        default:
            os << "<unprintable type " << type.tag() << ">";
    }
    return os;
}

std::ostream &
operator << (std::ostream &os, const ArgPrint &ap)
{
    Dwarf::ProcessLocation location = ap.pframe.frame.scopeIP(ap.p);
    if (!location.die() || !ap.pframe.options.doargs)
        return os;
    using namespace Dwarf;
    const char *sep = "";
    for (auto child : location.die().children()) {
        switch (child.tag()) {
            case DW_TAG_formal_parameter: {
                auto name = child.name();
                auto type = DIE(child.attribute(DW_AT_type));
                Elf::Addr addr = 0;
                os << sep << name;
                if (type) {
                    auto attr = child.attribute(Dwarf::DW_AT_location);

                    if (attr.valid()) {
                        Dwarf::ExpressionStack fbstack;
                        addr = fbstack.eval(ap.p, attr, &ap.pframe.frame, location.elfReloc);
                        os << "=";
                        try {
                           if (fbstack.isReg)
                              os << ProcPtr(ap.p, type, addr) << "{r" << fbstack.inReg << "}";
                           else
                              os << RemoteValue(ap.p, addr, type);
                        }
                        catch (const Exception &ex) {
                           os << "<" << ex.what() << ">";
                        }

                    } else {
                        auto constVal = child.attribute(Dwarf::DW_AT_const_value);
                        if (constVal.valid())
                            os << "=" << intmax_t(constVal);
                    }
                }
                sep = ", ";
                break;
            }
            default:
                break;
        }
    }
    return os;
}

std::ostream &operator << (std::ostream &os, Dwarf::UnwindMechanism mech) {
   switch (mech) {
      case Dwarf::UnwindMechanism::MACHINEREGS: return os << "machine registers";
      case Dwarf::UnwindMechanism::DWARF: return os << "DWARF";
      case Dwarf::UnwindMechanism::FRAMEPOINTER: return os << "frame pointer";
      case Dwarf::UnwindMechanism::BAD_IP_RECOVERY: return os << "popped faulting IP";
      case Dwarf::UnwindMechanism::TRAMPOLINE: return os << "signal trampoline";
      case Dwarf::UnwindMechanism::LOGFILE: return os << "log file";
      case Dwarf::UnwindMechanism::INVALID: return os << "invalid";
   }
   abort();
}

std::ostream &
Process::dumpStackText(std::ostream &os, const ThreadStack &thread,
      const PstackOptions &options) const
{
    os << std::dec;
    os << "thread: " << (void *)thread.info.ti_tid << ", lwp: "
       << thread.info.ti_lid << ", type: " << thread.info.ti_type << "\n";
    int frameNo = 0;
    for (auto &frame : thread.stack)
        dumpFrameText(os, PrintableFrame(*this, frame, frameNo++, options), frame);
    return os;
}

std::ostream &
Process::dumpFrameText(std::ostream &os, const PrintableFrame &pframe, const Dwarf::StackFrame &frame) const
{

    IOFlagSave _(os);

    Dwarf::ProcessLocation location = pframe.frame.scopeIP(pframe.proc);
    auto source = location.source();
    std::pair<std::string, int> src = source.size() ? source[0] : std::make_pair( "", std::numeric_limits<Elf::Addr>::max());
    for (auto i = pframe.inlined.rbegin(); i != pframe.inlined.rend(); ++i) {
       os << "#"
           << std::left << std::setw(2) << std::setfill(' ') << pframe.frameNumber << " "
           << std::setw(ELF_BITS/4 + 2) << std::setfill(' ')
           << "inlined";
       if (verbose > 0) {
           os << std::setw(ELF_BITS/4 + 2) << std::setfill(' ') << "/";
           os << " ";
       }
       os << " in ";
       ::dieName(os, *i);
       auto lineinfo = i->getUnit()->getLines();
       if (lineinfo) {
          os << " at " << src.first << ":" << src.second;
          auto &fileEnt = lineinfo->files[intmax_t(i->attribute(Dwarf::DW_AT_call_file))];
          auto &dirname = lineinfo->directories[fileEnt.dirindex];
          const auto &name = verbose ? dirname + "/" + fileEnt.name : fileEnt.name;
          src = std::make_pair( name, intmax_t(i->attribute(Dwarf::DW_AT_call_line)));
          os << "\n";
       }
    }

    os << "#"
        << std::left << std::setw(2) << std::setfill(' ') << pframe.frameNumber << " "
        << std::right << "0x" << std::hex << std::setw(ELF_BITS/4) << std::setfill('0')
        << frame.rawIP();

    os << std::dec;

    if (location.valid()) {
        std::string name;
        std::string flags = "";
        if (frame.isSignalTrampoline)
            flags += "*";

        auto sym = location.symbol();
        if (pframe.dieName != "") {
            name = pframe.dieName;
        } else if (sym) {
            name = sym->second;
            flags += location.die() ? "%" : "!";
        } else {
            name = "<unknown>";
        }
        os << " in "
            << name
            << flags
            << "(" << ArgPrint(*this, pframe) << ")";

        if (pframe.functionOffset != std::numeric_limits<Elf::Addr>::max())
            os << "+" << pframe.functionOffset;
        os << " in " << stringify(*location.elf()->io);
        if (verbose)
           os << "@0x" << std::hex << frame.rawIP() - location.elfReloc << std::dec;
        if (src.first != "")
           os << " at " << src.first << ":" << std::dec << src.second;
    } else {
        os << " no information for frame";
    }
    if (verbose)
       os << " via " << frame.mechanism;
    os << "\n";
    return os;
}

void
Process::addElfObject(Elf::Object::sptr obj, Elf::Addr load)
{
    objects[load] = obj;
    if (verbose >= 2) {
        IOFlagSave _(*debug);
        *debug << "object " << *obj->io << " loaded at address "
           << std::hex << load << std::dec << std::endl;
    }
}

/*
 * Grovel through the rtld's internals to find any shared libraries.
 */
void
Process::loadSharedObjects(Elf::Addr rdebugAddr)
{

    struct r_debug rDebug;
    io->readObj(rdebugAddr, &rDebug);

    /* Iterate over the r_debug structure's entries, loading libraries */
    struct link_map map;
    for (auto mapAddr = Elf::Addr(rDebug.r_map); mapAddr != 0; mapAddr = Elf::Addr(map.l_next)) {
        io->readObj(mapAddr, &map);

        // If we see the executable, just add it in and avoid going through the path
        // replacement work
        if (mapAddr == Elf::Addr(rDebug.r_map)) {
            auto loadAddr = entry - execImage->getHeader().e_entry;
            if (loadAddr != map.l_addr) {
                *debug << "calculated load address for executable from process entrypoint ("
                << std::hex << loadAddr << ") does not match link map (" << map.l_addr
                << "). Trusting link-map\n" << std::dec;
            }
            addElfObject(execImage, map.l_addr);
            continue;
        }
        // If we've loaded the VDSO, and we see it in the link map, just skip it.
        if (vdsoBase != 0 && map.l_addr == vdsoBase)
           continue;

        // Read the path to the file
        if (map.l_name == 0)
            continue;

        std::string path = io->readString(Elf::Off(map.l_name));
        if (path == "")
            continue;
        try {
            addElfObject(imageCache.getImageForName(path), Elf::Addr(map.l_addr));
        }
        catch (const std::exception &e) {
            std::clog << "warning: can't load text for '" << path << "' at " <<
            (void *)mapAddr << "/" << (void *)map.l_addr << ": " << e.what() << "\n";
            continue;
        }
    }
}

Elf::Addr
Process::findRDebugAddr()
{
    /*
     * Calculate the address the executable was loaded at - we know the entry
     * supplied by the kernel, and also the executable's desired entrypoint -
     * the difference is the load address.
     */
    Elf::Off loadAddr = entry - execImage->getHeader().e_entry;

    // Find DT_DEBUG in the process's dynamic section.
    for (auto &segment : execImage->getSegments(PT_DYNAMIC)) {
        // Read from the process, not the executable - the linker will have updated the content.
        auto dynReader = io->view("PT_DYNAMIC segment", segment.p_vaddr + loadAddr, segment.p_filesz);
        ReaderArray<Elf::Dyn> dynamic(*dynReader);
        for (auto dyn : dynamic)
            if (dyn.d_tag == DT_DEBUG && dyn.d_un.d_ptr != 0)
                return dyn.d_un.d_ptr;
    }
    /*
     * If there's no DT_DEBUG, we've probably got someone executing a shared
     * library, which doesn't have an _r_debug symbol. Use the address of
     * _r_debug in the interpreter
     */
    if (interpBase && execImage->getInterpreter() != "") {
        try {
            addElfObject(imageCache.getImageForName(execImage->getInterpreter()), interpBase);
            return resolveSymbol("_r_debug", false,
                  [this](const Elf::Addr, const Elf::Object::sptr &o) {
                      auto name = stringify(*o->io);
                      return execImage->getInterpreter() == name;
                  });
        }
        catch (...) {
        }
    }
    return 0;
}

namespace std {
bool
operator < (const std::pair<Elf::Addr, Elf::Object::sptr> &entry, Elf::Addr addr) {
   return entry.first < addr;
}
}

std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *>
Process::findSegment(Elf::Addr addr) const
{
    auto it = std::lower_bound(objects.begin(), objects.end(), addr);
    if (it != objects.begin()) {
       --it;
       if (it->first  + it->second->endVA() >= addr) {
           auto segment = it->second->getSegmentForAddress(addr - it->first);
           if (segment)
               return std::make_tuple(it->first, it->second, segment);
       }
    }
    return std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *>();
}

std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Sym>
Process::resolveSymbolDetail(const char *name, bool includeDebug,
        std::function<bool(Elf::Addr, const Elf::Object::sptr&)> match) const
{
    for (auto &loaded : objects) {
        if (!match(loaded.first, loaded.second))
           continue;
        auto sym = loaded.second->findDynamicSymbol(name);
        if (sym.st_shndx != SHN_UNDEF)
           return std::make_tuple(loaded.second, loaded.first, sym);
        if (includeDebug) {
           auto sym = loaded.second->findDebugSymbol(name);
           if (sym.st_shndx != SHN_UNDEF)
              return std::make_tuple(loaded.second, loaded.first, sym);
        }
    }
    throw (Exception() << "symbol " << name << " not found");
}

Elf::Addr
Process::resolveSymbol(const char *name, bool includeDebug,
        std::function<bool(Elf::Addr, const Elf::Object::sptr&)> match) const
{
    auto info = resolveSymbolDetail(name, includeDebug, match);
    return std::get<1>(info) + std::get<2>(info).st_value;

}

Process::~Process()
{
    // don't leave the VDSO in the cache - a new copy will be entered for a new
    // process.
    imageCache.flush(vdsoImage);
    td_ta_delete(agent);
}

void
ThreadStack::unwind(Process &p, Elf::CoreRegisters &regs, unsigned maxFrames)
{
    stack.clear();
    stack.reserve(20);

#ifdef __aarch64__
    auto sigreturnSym = p.vdsoImage->findDynamicSymbol("__kernel_rt_sigreturn");
    Elf::Addr trampoline = sigreturnSym.st_shndx == SHN_UNDEF ? 0 : sigreturnSym.st_value + p.vdsoBase;
#endif

    try {
        stack.emplace_back(Dwarf::UnwindMechanism::MACHINEREGS, regs);

        // Set up the first frame using the machine context registers
        stack.front().setCoreRegs(regs);

        for (size_t frameCount = 0; frameCount < maxFrames; frameCount++) {
            auto &prev = stack.back();

            try {
                auto maybeNewRegs = prev.unwind(p);
                if (!maybeNewRegs)
                    break;
                auto &newRegs = *maybeNewRegs;
                stack.emplace_back(Dwarf::UnwindMechanism::DWARF, newRegs);
#ifdef __aarch64__
                auto &cur = stack.back();
                if (Elf::getReg(newRegs, 32) == trampoline)
                    cur.isSignalTrampoline = true;
#endif
            }
            catch (const std::exception &ex) {

                if (verbose > 2)
                    *debug << "failed to unwind frame with DWARF: "
                           << ex.what() << std::endl;

                // Some machine specific methods of unwinding if DWARF fails.

                // if we're the top-of-stack, or there's a signal handler just
                // above, and the instruction pointer in the current frame
                // doesn't look like it comes from a code segment, then there's
                // a strong likelihood that we jumped to an invalid location
                // from an indirect call. The only action carried out for the
                // frame is that the call instruction pushed the return address
                // onto the stack. The calling frame is an exact copy of the
                // called one, but with the instruction pointer read from the
                // TOS, and the stack pointer adjusted.
                //
                // If we're wrong here, it's possible we do worse than we would
                // have done had we fallen down to rame pointer unwinding, but
                // we'd need to be executing an instruction in a piece of
                // runtime-generated code, or something else that wasn't in a
                // normal ELF phdr, so it seems more likely this is the best
                // thing to do.
                //
                // For ARM, the concept is the same, but we look at the link
                // register rather than a pushd return address

#if defined(__amd64__)
#define BP(regs) (regs.rbp)
#define SP(regs) (regs.rsp)
#define IP(regs) (regs.rip)
#elif defined(__i386__)
#define BP(regs) regs.ebp
#define SP(regs) regs.esp
#define IP(regs) (regs.eip)
#endif

                auto newRegs = prev.regs; // start with a copy of prev frames regs.

                if (stack.size() == 1 || prev.isSignalTrampoline) {
                    Dwarf::ProcessLocation prevlocation = prev.scopeIP(p);
                    Dwarf::ProcessLocation location(p, IP(newRegs));
                    if (!prevlocation.valid() || (location.valid() && (location.codeloc->phdr_->p_flags & PF_X) == 0)) {

#if defined(__amd64__) || defined(__i386__)
                        // get stack pointer in the current frame, and read content of TOS
                        auto sp = SP(prev.regs);
                        Elf::Addr ip;
                        auto in = p.io->read(sp, sizeof ip, (char *)&ip);
                        if (in == sizeof ip) {
                            SP(newRegs) = sp + sizeof ip;
                            IP(newRegs) = ip;             // .. insn pointer.
                            stack.emplace_back(Dwarf::UnwindMechanism::BAD_IP_RECOVERY, newRegs);
                            continue;
                        }
#elif defined(__aarch64__)
                        newRegs[32] = prev.regs[30]; // Copy old link register into new instruction pointer.
                        stack.emplace_back(Dwarf::UnwindMechanism::BAD_IP_RECOVERY, newRegs);
                        continue;
#endif
                    }
                }
#if defined(__aarch64__)
                // This is as per arch/arm64/kernel/signal.c
                struct rt_sigframe {
                   siginfo_t si;
                   ucontext_t uc;
                };

                if (trampoline && trampoline == prev.rawIP()) {
                    auto sigframe = p.io->readObj<rt_sigframe>(Elf::getReg(prev.regs, 31));
                    for (int i = 0; i < 31; ++i)
                       newRegs[i] = sigframe.uc.uc_mcontext.regs[i];
                    newRegs[31] = sigframe.uc.uc_mcontext.sp;
                    newRegs[32] sigframe.uc.uc_mcontext.pc;
                    stack.emplace_back(Dwarf::UnwindMechanism::TRAMPOLINE, newRegs);
                    continue;
                }

#elif defined(__i386__)
                // Deal with signal trampolines for i386
                Elf::Addr reloc;
                const Elf::Phdr *segment;
                Elf::Object::sptr obj;
                std::tie(reloc, obj, segment) = p.findSegment(prev.rawIP());
                if (obj) {
                    Elf::Addr sigContextAddr = 0;
                    auto objip = prev.rawIP() - reloc;
                    auto restoreSym = obj->findDebugSymbol("__restore");
                    if (restoreSym.st_shndx != SHN_UNDEF && objip == restoreSym.st_value)
                        sigContextAddr = SP(prev.regs) + 4;
                    else {
                        auto restoreRtSym = obj->findDebugSymbol("__restore_rt");
                        if (restoreRtSym.st_shndx != SHN_UNDEF && objip == restoreRtSym.st_value)
                            sigContextAddr = p.io->readObj<Elf::Addr>(SP(prev.regs) + 8) + 20;
                    }
                    if (sigContextAddr != 0) {
                       // This mapping is based on DWARF regnos, and ucontext.h
                       gregset_t regs;
                       p.io->readObj(sigContextAddr, &regs);
                       Elf::CoreRegisters core;
                       gregset2core(core, regs);
                       stack.emplace_back(Dwarf::UnwindMechanism::TRAMPOLINE, core);
                       continue;
                    }
                }
#endif

#if defined(__i386__) || defined(__amd64__)
                // frame-pointer unwinding.
                // Use ebp/rbp to find return address and saved BP.
                // Restore those, and the stack pointer itself.
                //
                // We skip this if the instruction pointer is zero - we hope
                // we'd have resolved null-pointer calls above, and if we find
                // a 0 ip on the call stack, it's a good indication the
                // unwinding is finished.
                if (prev.rawIP() != 0) {
                   Elf::Addr newBp, newIp, oldBp;
                   oldBp = BP(prev.regs);
                   if (oldBp == 0) {
                      // null base pointer means we're done.
                      break;
                   }
                   p.io->readObj(oldBp + ELF_BYTES, &newIp);
                   p.io->readObj(oldBp, &newBp);
                   if (newBp > oldBp && newIp > 4096) {
                       SP(newRegs) = oldBp + ELF_BYTES * 2;
                       BP(newRegs) = newBp;
                       IP(newRegs) = newIp;
                       stack.emplace_back(Dwarf::UnwindMechanism::FRAMEPOINTER, newRegs);
                       stack.back().cfa = newBp;
                       continue;
                   }
                }
#endif
                throw;
            }
        }
    }
    catch (const std::exception &ex) {
        std::clog << "warning: exception unwinding stack: " << ex.what() << std::endl;
    }
}

std::shared_ptr<Process> Process::load(Elf::Object::sptr exec, std::string id, const PstackOptions &options, Dwarf::ImageCache &imageCache) {
    pid_t pid;
    std::istringstream(id) >> pid;
    std::shared_ptr<Process> proc;
    if (pid != 0) {
       if (kill(pid, 0) == 0)
          proc = std::make_shared<LiveProcess>(exec, pid, options, imageCache);
       else
          throw Exception() << "process " << pid << ": " << strerror(errno);
    } else {
       // don't use imagecache for cores. We don't want to mmap them (they can
       // be enormous, esp. from a leaky process), use loadFile and a caching
       // reader on the underlying file instead.
       auto core = std::make_shared<Elf::Object>(imageCache, loadFile(id));
       if (core->getHeader().e_type != ET_CORE)
          return nullptr; // image is ELF, but not a core - just return null
       proc = std::make_shared<CoreProcess>(exec, core, options, imageCache);
    }
    proc->load();
    return proc;
}


std::list<ThreadStack>
Process::getStacks(const PstackOptions &options, unsigned maxFrames) {
    std::list<ThreadStack> threadStacks;
    std::set<pid_t> tracedLwps;
    StopProcess processSuspender(this);

    /*
     * First find "threads", the userland pthread_t concept. This uses the
     * pthread "agent". This is the userland-visible part of the threading
     * system, and allows us to find pthread ids, and (in theory) deal with
     * threading systems where there is not a 1:1 correspondence between
     * userland pthreads and kernel LWPs
     */
    listThreads([this, &threadStacks, &tracedLwps, maxFrames] (
                       const td_thrhandle_t *thr) {
        Elf::CoreRegisters regs;
        td_err_e the;
#ifdef __linux__
        the = td_thr_getgregs(thr, (elf_greg_t *) &regs);
#else
        the = td_thr_getgregs(thr, &regs);
#endif
        if (the == TD_OK) {
            threadStacks.push_back(ThreadStack());
            td_thr_get_info(thr, &threadStacks.back().info);
            threadStacks.back().unwind(*this, regs, maxFrames);
            tracedLwps.insert(threadStacks.back().info.ti_lid);
        }
    });

     /*
      * Now find LWPs, the kernel scheduled entities.  If we saw a thread above
      * with this LWP assigned as its `ti_lid` field then that thread was the
      * one actively scheduled on this LWP, so there's no need to print out its
      * backtrace. We assume that in a system where N(threads) != N(lwps), then
      * threads that are not currently scheduled would get their register set
      * from somewhere other than the LWP (eg, cached in some structure that
      * td_thr_getregs would have found without resorting to ps_lgetregs().
      * There are no extant linux systems that I'm aware of that use a non-1:1
      * thread model, so we can't really test this.
      */
    for (auto &lwp : lwps) {
        if (tracedLwps.find(lwp.first) == tracedLwps.end()) {
            threadStacks.push_back(ThreadStack());
            threadStacks.back().info.ti_lid = lwp.first;
            Elf::CoreRegisters regs;
            getRegs(lwp.first,  &regs);
            threadStacks.back().unwind(*this, regs, maxFrames);
        }
    }

    /*
     * if we don't need to print arguments to functions, we now have the full
     * backtrace and don't need to read anything more from the process.
     * Everything else is just parsing debug data, so we can resume now.
     */
    if (!options.doargs)
        processSuspender.clear();

    return threadStacks;
}


std::ostream & operator << (std::ostream &os, WaitStatus ws) {
   if (WIFSIGNALED(ws.status)) {
      os << "signal(" << strsignal(WTERMSIG(ws.status)) << ")";
      if (WCOREDUMP(ws.status))
         os << "(core dumped)";
   }
   else if (WIFSTOPPED(ws.status))
      os << "stop(" << strsignal(WSTOPSIG(ws.status)) << ")";
   else if (WIFEXITED(ws.status))
      os << "exit(" << WEXITSTATUS(ws.status) << ")";
   return os;
}

