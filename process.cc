#include <features.h>

#define REGMAP(a,b)
#include "libpstack/dwarf/archreg.h"
#include "libpstack/dwarf.h"
#include "libpstack/proc.h"
#include "libpstack/ps_callback.h"

#include <link.h>
#include <unistd.h>

#include <cassert>
#include <climits>

#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <sys/ucontext.h>

static size_t gMaxFrames = 1024; /* max number of frames to read */

Process::Process(Elf::Object::sptr exec, Reader::csptr memory,
                  const PathReplacementList &prl, Dwarf::ImageCache &cache)
    : entry(0)
    , interpBase(0)
    , isStatic(false)
    , vdsoBase(0)
    , agent(nullptr)
    , execImage(std::move(exec))
    , pathReplacements(prl)
    , sysent(0)
    , imageCache(cache)
    , io(std::move(memory))
{
    if (execImage)
        entry = execImage->getHeader().e_entry;
}

void
Process::load(const PstackOptions &options)
{
    /*
     * Attach the executable and any shared libs.
     * The process is still running here, but unless its actively loading or
     * unload a shared library, this relatively safe, and saves us a lot of
     * work while the process is stopped.
     */

    if (!execImage)
        throw (Exception() << "no executable image located for process");

    Elf::Addr r_debug_addr = findRDebugAddr();
    isStatic = r_debug_addr == 0 || r_debug_addr == Elf::Addr(-1);
    if (isStatic)
        addElfObject(execImage, 0);
    else
        loadSharedObjects(r_debug_addr);

    if (!options[PstackOption::nothreaddb]) {
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
Process::getDwarf(Elf::Object::sptr elf)
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
                    struct VDSOReader : public OffsetReader {
                        void describe(std::ostream &os) const override {
                            os << "(vdso image)";
                        }
                        VDSOReader( Reader::csptr up, off_t start, off_t length) :
                            OffsetReader(std::move(up), start, length) {}
                    };
                    auto elf = std::make_shared<Elf::Object>(imageCache,
                                    std::make_shared<VDSOReader>(io, hdr, 65536));
                    vdsoBase = hdr;
                    addElfObject(elf, hdr);
                    vdsoImage = elf;
                    if (verbose >= 2) {
                        *debug << "auxv: VDSO " << *elf->io
                           << " loaded at " << std::hex << hdr << "\n";
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
                auto exeName = io->readString(hdr);
                if (verbose >= 2)
                    *debug << "filename from auxv: " << exeName << "\n";
                if (!execImage) {
                    execImage = imageCache.getImageForName(exeName);
                    if (entry == 0)
                       entry = execImage->getHeader().e_entry;
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
   // use the specification DIE instead of this if we have one.
   auto spec = die.attribute(Dwarf::DW_AT_specification);
   if (spec.valid()) {
      return dieName(os, Dwarf::DIE(spec), first);
   }
   auto parent = die.getParentOffset();
   bool printedParent = parent != 0 && dieName(os, die.getUnit()->offsetToDIE(parent), false);
   if (die.tag() != Dwarf::DW_TAG_compile_unit) { // don't print out compile unit
      if (printedParent)
         os << "::";
      os << die.name();
      return true;
   }
   return printedParent;
}

struct PrintableFrame {
    int frameNumber;
    std::string dieName;
    std::string symName;
    Elf::Sym symbol;
    std::vector<std::pair<std::string, int>> source;
    bool isSignalFrame;
    const PstackOptions &options;
    Elf::Addr functionOffset;
    bool haveSym;

    PrintableFrame(Dwarf::StackFrame *frame, int frameNo, const PstackOptions &options)
        : frameNumber(frameNo)
        , isSignalFrame(frame->cie != nullptr && frame->cie->isSignalHandler)
        , options(options)
        , functionOffset(std::numeric_limits<Elf::Addr>::max())
        , haveSym(false)
    {
        if (frame->elf == nullptr)
            return;
        Elf::Addr objIp = frame->scopeIP() - frame->elfReloc;
        Dwarf::Unit::sptr dwarfUnit = frame->dwarf->lookupUnit(objIp);
        if (dwarfUnit == nullptr) {
            // no ranges - try each dwarf unit in turn. (This seems to happen
            // for single-unit exe's only, so it's no big loss)
            for (const auto &u : frame->dwarf->getUnits()) {
                frame->function = Dwarf::findEntryForFunc(objIp, u->root());
                if (frame->function)
                    break;
            }
        } else {
            frame->function = Dwarf::findEntryForFunc(objIp, dwarfUnit->root());
        }

        if (frame->function) {
            std::ostringstream sos;
            ::dieName(sos, frame->function);
            this->dieName = sos.str();

            auto lowpc = frame->function.attribute(Dwarf::DW_AT_low_pc);
            if (lowpc.valid())
                functionOffset = objIp - uintmax_t(lowpc);
        }

        if (!options[PstackOption::nosrc])
            source = frame->dwarf->sourceFromAddr(objIp);

        haveSym = frame->elf->findSymbolByAddress(objIp, STT_FUNC, symbol, symName);
        if (haveSym && functionOffset == std::numeric_limits<Elf::Addr>::max())
            functionOffset = objIp - symbol.st_value;

    }
    PrintableFrame(const PrintableFrame &) = delete;
    PrintableFrame() = delete;
};


std::ostream &
operator << (std::ostream &os, const JSON<std::pair<std::string, int>> &jt)
{
    return JObject(os)
        .field("file", jt.object.first)
        .field("line", jt.object.second);
}

std::ostream &
operator << (std::ostream &os, const JSON<std::pair<Elf::Sym *, std::string>> &js)
{
    const auto &obj = js.object;
    return JObject(os)
        .field("st_name", obj.second)
        .field("st_value", obj.first->st_value)
        .field("st_size", obj.first->st_size)
        .field("st_info", int(obj.first->st_info))
        .field("st_other", int(obj.first->st_other))
        .field("st_shndx", obj.first->st_shndx);
}

std::ostream &
operator << (std::ostream &os, const JSON<Dwarf::StackFrame *, Process *> &jt)
{
    auto &frame =jt.object;
    PstackOptions options;
    options[doargs] = true;
    PrintableFrame pframe(frame, 0, options);

    JObject jo(os);
    jo
        .field("ip", frame->rawIP());
    if (frame->elf)
        jo
            .field("object", stringify(*frame->elf->io))
            .field("loadaddr", frame->elfReloc)
            .field("source", pframe.source)
            .field("die", pframe.dieName)
            .field("cfa", frame->cfa)
            .field("offset", pframe.functionOffset)
            .field("trampoline", pframe.isSignalFrame)
        ;
    if (pframe.haveSym)
        jo.field("symbol", std::make_pair(&pframe.symbol, pframe.symName));
    else
        jo.field("symbol", JsonNull());

    return jo;
}

std::ostream &
operator << (std::ostream &os, const JSON<ThreadStack, Process *> &ts)
{
    return JObject(os)
        .field("ti_tid", ts->info.ti_tid)
        .field("ti_type", ts->info.ti_type)
        .field("ti_stack", ts->stack, ts.context);
}

struct ArgPrint {
    const Process &p;
    const struct Dwarf::StackFrame *frame;
    const PstackOptions &options;
    ArgPrint(const Process &p_, const Dwarf::StackFrame *frame_, const PstackOptions &options_)
        : p(p_), frame(frame_), options(options_) {}
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
    for (base = DIE(pp.type.attribute(DW_AT_type)); base && base.tag() == DW_TAG_const_type;) {
        base = DIE(base.attribute(DW_AT_type));
    }

    if (base && base.name() == "char") {
       std::string s = pp.proc.io->readString(pp.addr);
       os << "\"" << s << "\"";
    } else {
       os << (void *)pp.addr;
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
    if (!ap.frame->function || !ap.options[PstackOption::doargs])
        return os;
    using namespace Dwarf;
    const char *sep = "";
    for (auto child : ap.frame->function.children()) {
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
                        addr = fbstack.eval(ap.p, attr, ap.frame, ap.frame->elfReloc);
                        os << "=";
                        if (fbstack.isReg) {
                           os << ProcPtr(ap.p, type, addr)
                              << "{r" << fbstack.inReg << "}";
                        } else {
                           os << RemoteValue(ap.p, addr, type);
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
    for (auto frame : thread.stack)
        dumpFrameText(os, PrintableFrame(frame, frameNo, options), frame);
    return os;
}

std::ostream &
Process::dumpFrameText(std::ostream &os, const PrintableFrame &pframe,
        Dwarf::StackFrame *frame) const
{

    IOFlagSave _(os);

    os << std::hex;
    os << "#"
        << std::left << std::setw(2) << std::setfill(' ') << pframe.frameNumber << " "
        << std::right << "0x" << std::setw(ELF_BITS/4) << std::setfill('0')
        << frame->rawIP();

    if (verbose > 0)
        os << "/" << "0x" << std::setw(ELF_BITS/4) << std::setfill('0') << frame->cfa;
    os << std::dec;
    os << " ";

    if (frame->elf) {
        std::string name;
        std::string flags = "";
        if (pframe.isSignalFrame)
            flags += "*";
        if (pframe.dieName != "") {
            name = pframe.dieName;
        } else if (pframe.symName != "") {
            name = pframe.symName;
            flags += frame->function ? "%" : "!";
        } else {
            name = "<unknown>";
        }
        os << " in "
            << name
            << flags
            << "(" << ArgPrint(*this, frame, pframe.options) << ") ";

        if (pframe.functionOffset != std::numeric_limits<Elf::Addr>::max())
            os << "+" << pframe.functionOffset;
        os << " in " << stringify(*frame->elf->io);
        for (auto &ent : pframe.source)
            os << " at " << ent.first << ":" << std::dec << ent.second;
    } else {
        os << "no information for frame";
    }
    if (verbose)
       os << " via " << frame->mechanism;
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
           << std::hex << load << std::endl;
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
            assert(map.l_addr == entry - execImage->getHeader().e_entry);
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

        std::string startPath = path;
        for (auto &it : pathReplacements) {
            size_t found = path.find(it.first);
            if (found != std::string::npos)
                path.replace(found, it.first.size(), it.second);
        }
        if (verbose > 0 && path != startPath)
            *debug << "replaced " << startPath << " with " << path << std::endl;

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
        OffsetReader dynReader(io, segment.p_vaddr + loadAddr, segment.p_filesz);
        ReaderArray<Elf::Dyn> dynamic(dynReader);
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
            return findSymbol("_r_debug", false,
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
   return entry.second->endVA() + entry.first < addr;
}
}

std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *>
Process::findObject(Elf::Addr addr) const
{
    auto it = std::lower_bound(objects.begin(), objects.end(), addr);
    if (it != objects.end()) {
        auto segment = it->second->getSegmentForAddress(addr - it->first);
        if (segment)
            return std::make_tuple(it->first, it->second, segment);
    }
    return std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *>();
}

Elf::Addr
Process::findSymbol(const char *name, bool includeDebug,
        std::function<bool(Elf::Addr, const Elf::Object::sptr&)> match) const
{
    Elf::Sym sym;
    for (auto &loaded : objects)
        if (match(loaded.first, loaded.second) &&
            (loaded.second->findDynamicSymbol(name, sym) ||
                    (includeDebug && loaded.second->findDebugSymbol(name, sym)))) {
                auto rv = sym.st_value + loaded.first;
                if (verbose >= 3)
                   *debug << "found symbol '" << name << "' at "<< rv << std::endl;
                return rv;
        }
    Exception e;
    e << "symbol " << name << " not found";
    throw e;
}

Process::~Process()
{
    // don't leave the VDSO in the cache - a new copy will be entered for a new
    // process.
    imageCache.flush(vdsoImage);
    td_ta_delete(agent);
}

void
ThreadStack::unwind(Process &p, Elf::CoreRegisters &regs)
{
    stack.clear();
    try {
        auto curFrame = new Dwarf::StackFrame(Dwarf::UnwindMechanism::MACHINEREGS);
        auto startFrame = curFrame;
        const Dwarf::StackFrame *prevFrame = 0;

        // Set up the first frame using the machine context registers
        startFrame->setCoreRegs(regs);

        Dwarf::StackFrame *nextFrame;
        for (size_t frameCount = 0; frameCount < gMaxFrames; frameCount++,
              prevFrame = curFrame, curFrame = nextFrame) {
            if (curFrame == 0)
               break;
            stack.push_back(curFrame);
            nextFrame = 0;
            try {
               nextFrame = curFrame->unwind(p);
            }
            catch (const std::exception &ex) {

                if (verbose > 2)
                    *debug << "failed to unwind frame with DWARF: "
                           << ex.what() << std::endl;

                // Some machine specific methods of unwinding if DWARF fails.

#if defined(__amd64__) || defined(__i386__)
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
                // have done had we fallen down to frame pointer unwinding, but
                // we'd need to be executing an instruction in a piece of
                // runtime-generated code, or something else that wasn't in a
                // normal ELF phdr, so it seems more likely this is the best
                // thing to do.
                if ((curFrame == startFrame ||
                         (prevFrame->cie && prevFrame->cie->isSignalHandler)) &&
                   (curFrame->phdr == 0 || (curFrame->phdr->p_flags & PF_X) == 0)) {
                    nextFrame = new Dwarf::StackFrame(*curFrame,
                          Dwarf::UnwindMechanism::BAD_IP_RECOVERY);
                    // get stack pointer in the current frame, and read content of
                    // TOS
                    auto sp = curFrame->getReg(SPREG);
                    Elf::Addr ip;
                    auto in = p.io->read(sp, sizeof ip, (char *)&ip);
                    if (in == sizeof ip) {
                        nextFrame->setReg(SPREG, sp + sizeof ip); // pop...
                        nextFrame->setReg(IPREG, ip);             // .. insn pointer.
                        continue;
                    }
                }
#endif

#ifdef __i386__
                // Deal with signal trampolines for i386
                Elf::Addr reloc;
                const Elf::Phdr *segment;
                Elf::Object::sptr obj;
                std::tie(reloc, obj, segment) = p.findObject(curFrame->rawIP());
                if (obj) {
                    Elf::Sym symbol;
                    Elf::Addr sigContextAddr = 0;
                    auto objip = curFrame->rawIP() - reloc;
                    if (obj->findDebugSymbol("__restore", symbol) && objip == symbol.st_value)
                        sigContextAddr = curFrame->getReg(SPREG) + 4;
                    else if (obj->findDebugSymbol("__restore_rt", symbol) && objip == symbol.st_value)
                        sigContextAddr = p.io->readObj<Elf::Addr>(curFrame->getReg(SPREG) + 8) + 20;
                    if (sigContextAddr != 0) {
                       // This mapping is based on DWARF regnos, and ucontext.h
                       gregset_t regs;
                       static const struct {
                           int dwarf;
                           int greg;
                       }  gregmap[] = {
                           { 1, REG_EAX },
                           { 2, REG_ECX },
                           { 3, REG_EBX },
                           { 4, REG_ESP },
                           { 5, REG_EBP },
                           { 6, REG_ESI },
                           { 7, REG_EDI },
                           { 8, REG_EIP },
                           { 9, REG_EFL },
                           { 10, REG_CS },
                           { 11, REG_SS },
                           { 12, REG_DS },
                           { 13, REG_ES },
                           { 14, REG_FS }
                       };
                       p.io->readObj(sigContextAddr, &regs);
                       nextFrame = new Dwarf::StackFrame(*curFrame,
                             Dwarf::UnwindMechanism::TRAMPOLINE);
                       for (auto &reg : gregmap)
                           nextFrame->setReg(reg.dwarf, regs[reg.greg]);
                       continue;
                    }
                }
#endif

#if defined(__i386__) || defined(__amd64__)
                // frame-pointer unwinding.
                // Use ebp/rbp to find return address and saved BP.
                // Restore those, and the stack pointer itself.
                Elf::Addr newBp, newIp, oldBp;
                oldBp = curFrame->getReg(BPREG);
                if (oldBp == 0)
                   return; // null base pointer means we're done.
                p.io->readObj(oldBp + ELF_BYTES, &newIp);
                p.io->readObj(oldBp, &newBp);
                if (newBp > oldBp && newIp > 4096) {
                    nextFrame = new Dwarf::StackFrame(*curFrame,
                          Dwarf::UnwindMechanism::FRAMEPOINTER);
                    nextFrame->setReg(SPREG, oldBp + ELF_BYTES * 2);
                    nextFrame->setReg(BPREG, newBp);
                    nextFrame->setReg(IPREG, newIp);
                    continue;
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
