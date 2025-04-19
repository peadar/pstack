#include <features.h>

#include <link.h>
#include <unistd.h>
#include <charconv>

#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <csignal>
#include <sys/signal.h>

#include "libpstack/archreg.h"
#include "libpstack/dwarf.h"
#include "libpstack/proc.h"
#include "libpstack/stringify.h"
#include "libpstack/ioflag.h"

#if defined(__amd64__)
#define BP(regs) (regs.rbp)
#define SP(regs) (regs.rsp)
#define IP(regs) (regs.rip)
#elif defined(__i386__)
#define BP(regs) regs.ebp
#define SP(regs) regs.esp
#define IP(regs) (regs.eip)
#elif defined(__aarch64__)
#define IP(regs) (regs.pc)
#endif
namespace pstack {;

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
operator << (std::ostream &os, const JSON<Procman::ProcessLocation, Procman::Process *> &)
{
    return os;
}

std::ostream &
operator << (std::ostream &os, const JSON<Procman::StackFrame, Procman::Process *> &jt);

std::ostream &
operator << (std::ostream &os, const JSON<Procman::ThreadStack, Procman::Process *> &ts)
{
    return JObject(os)
        .field("ti_tid", ts.object.info.ti_tid)
        .field("ti_lid", ts.object.info.ti_lid)
        .field("ti_type", ts.object.info.ti_type)
        .field("ti_pri", ts.object.info.ti_pri)
        .field("ti_stack", ts.object.stack, ts.context);
}

}

namespace std {
bool
operator < (const std::pair<pstack::Elf::Addr, pstack::Elf::Object::sptr> &entry, pstack::Elf::Addr addr) {
   return entry.first < addr;
}
}

namespace pstack {
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

namespace Procman {

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


Process::Process(pstack::Context &context_, Elf::Object::sptr exec, Reader::sptr memory)
    : entry(0)
    , dt_debug(0)
    , interpBase(0)
    , vdsoBase(0)
    , agent(nullptr)
    , execImage(std::move(exec))
    , sysent(0)
    , context(context_)
    , io(std::move(memory))
{
    if (execImage) {
        // assume the entry point is that of the executable (correct for non-PIE/static)
        entry = execImage->getHeader().e_entry;
    }
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

    // by now, we should know what executable was loaded for the process.
    if (!execImage)
        throw (Exception() << "no executable image located for process");

    try {
        Elf::Addr r_debug_addr = findRDebugAddr();
        bool isStatic = r_debug_addr == 0 || r_debug_addr == Elf::Addr(-1);

        if (isStatic)
            addElfObject("", execImage, 0);
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

    if (!context.options.nothreaddb) {
        td_err_e the;
        the = td_ta_new(this, &agent);
        if (the != TD_OK) {
            agent = nullptr;
            if (context.verbose > 0 && the != TD_NOLIBTHREAD)
                *context.debug << "failed to load thread agent: " << the << std::endl;
        }
    }

}

Dwarf::Info::sptr
Process::getDwarf(Elf::Object::sptr elf) const
{
    return context.getDwarf(elf);
}


const char *
auxtype2str(int auxtype) {
#define AUX_TYPE(t, v) if (auxtype == t) return #t;
#include "libpstack/elf/auxv.h"
   return "unknown type";
#undef AUX_TYPE
}

void
Process::processAUXV(const Reader &auxio)
{
    std::string exeName;
    Elf::Addr phOff = 0;
    size_t phNum = 0;
    Elf::BuildID exeID;
    for (auto &aux : ReaderArray<Elf::auxv_t>(auxio)) {
        Elf::Addr hdr = aux.a_un.a_val;
        if (context.verbose > 2)
            *context.debug << "auxv: " << auxtype2str(aux.a_type) << ": " << hdr << std::endl;
        if (aux.a_type == AT_NULL)
           break;
        switch (aux.a_type) {
            case AT_ENTRY: {
                // this provides a reference for relocating the executable when
                // compared to the entrypoint in the image.
                entry = hdr;
                break;
            }
            case AT_SYSINFO:
                sysent = hdr;
                break;
            case AT_SYSINFO_EHDR: {
                try {
                    auto elf = std::make_shared<Elf::Object>(context, io->view("(vdso image)", hdr, 65536));
                    vdsoBase = hdr;
                    addElfObject("(vdso image)", elf, hdr);
                    vdsoImage = elf;
                    if (context.verbose >= 2) {
                        *context.debug << "auxv: VDSO " << *elf->io
                            << " loaded at " << std::hex << hdr << std::dec << "\n";
                    }

                }
                catch (const std::exception &ex) {
                    if (context.debug)
                        *context.debug << "auxv: warning: failed to load DSO: " << ex.what() << "\n";
                }
                break;
            }
            case AT_BASE:
                interpBase = hdr;
                break;
#ifdef AT_EXECFN
            case AT_EXECFN: {
                try {
                    exeName = io->readString(hdr);
                    if (context.verbose >= 2)
                        *context.debug << "filename from auxv: " << exeName << "\n";
                }
                catch (const Exception &ex) {
                    *context.debug << "failed to read AT_EXECFN: " << ex.what() << std::endl;
                }

                break;
            }
#endif
            case AT_PHDR:
               phOff = hdr;
               break;
            case AT_PHNUM:
               phNum = hdr;
               break;
            default:
               break;
        }
    }


    // If we have phdrs, process them. Use PT_PHDR to find the relocation ofset
    // between the phOff and the virtual addresses in the executable image.
    auto view = io->view("phdrs", phOff, sizeof (Elf::Phdr) * phNum);
    ReaderArray<Elf::Phdr> headers { *view };
    Elf::Addr vaOff = 0;
    std::optional<Elf::Phdr> ptDynamic;

    std::vector<Elf::Addr> notes;
    for ( auto phdr : headers ) {
        switch (phdr.p_type) {
            case PT_PHDR:
                // that's the diff between the va's in the process vs the image.
                // XXX: always before the notes?
                vaOff = phOff - phdr.p_vaddr;
                break;
            case PT_NOTE:
                notes.push_back(phdr.p_vaddr);
                break;

            case PT_DYNAMIC:
                ptDynamic = phdr;
                break;
        }
    }
    if (ptDynamic) {
        auto view = io->view( "dynamic table", ptDynamic->p_vaddr + vaOff, ptDynamic->p_memsz );
        for (auto dyn : ReaderArray<Elf::Dyn>(*view)) {
            if (dyn.d_tag == DT_DEBUG && dyn.d_un.d_ptr != 0) {
                dt_debug = dyn.d_un.d_ptr;
                if (context.verbose)
                    *context.debug << "found DT_DEBUG at " << std::hex << dt_debug << std::dec << " from auxv\n";
            }
        }
    }

    // Find the executable image - we'll need it to find DT_DEBUG.
    if (!execImage) {
        // search for a GNU_BUILD_ID note in the notes.
        for ( auto noteOff : notes) {
            auto noteVa = noteOff + vaOff;
            auto n = io->readObj<Elf::Note>( noteOff + vaOff );
            if (n.n_type != Elf::GNU_BUILD_ID)
                continue;
            std::vector<char> name(n.n_namesz);
            io->read(noteVa + sizeof n, name.size(), name.data());
            if (name[n.n_namesz - 1] == 0)
                name.resize(name.size() - 1);
            if (std::string_view(name.data(), name.size()) != "GNU")
                continue;
            exeID.data.resize(n.n_descsz);
            io->read(noteVa + sizeof n + 4, n.n_descsz, (char *)exeID.data.data());
            if (context.verbose)
                *context.debug << "build ID From AT_PHDR: " << exeID << "\n";
            break;
        }
        execImage = context.getImage(exeID);
    }

    if (!execImage && exeName != "")
       execImage = context.getImage(exeName);
    if (!execImage)
       execImage = executableImage(); // default to whatever the process can give us (eg, mmap /proc/<>/exe)
}

static bool
buildDIEName(std::ostream &os, const Dwarf::DIE &die, bool first=true) {
    // use the specification or abstract origin DIE instead of this if we have one.
    auto spec = die.attribute(Dwarf::DW_AT_specification);
    if (spec.valid())
        return buildDIEName(os, Dwarf::DIE(spec), first);
    auto origin = die.attribute(Dwarf::DW_AT_abstract_origin);
    if (origin.valid())
        return buildDIEName(os, Dwarf::DIE(origin), first);

    // Don't walk up past compile units.
    if (die.tag() == Dwarf::DW_TAG_compile_unit || die.tag() == Dwarf::DW_TAG_partial_unit)
        return false;

    auto parent = die.getParentOffset();
    bool printedParent = buildDIEName(os, die.getUnit()->offsetToDIE(Dwarf::DIE(), parent), false);

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

PrintableFrame::PrintableFrame(Process &proc, const StackFrame &frame)
    : proc(proc)
    , functionOffset(std::numeric_limits<Elf::Addr>::max())
    , frame(frame)
{
    auto location = frame.scopeIP(proc);

    if (location.elf() == nullptr)
        return;
    Elf::Addr objIp = location.objLocation();
    if (!proc.context.options.nodienames) {
        auto function = location.die();
        if (function) {
            std::ostringstream sos;
            buildDIEName(sos, function);
            this->dieName = sos.str();
            auto lowpc = function.attribute(Dwarf::DW_AT_low_pc);
            if (lowpc.valid()) {
                functionOffset = objIp - uintmax_t(lowpc);
            } else {
                const auto &ranges = function.getRanges();
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

Dwarf::DIE removeCV(Dwarf::DIE type) {
    while (type &&
          (type.tag() == Dwarf::DW_TAG_typedef
          || type.tag() == Dwarf::DW_TAG_const_type
          || type.tag() == Dwarf::DW_TAG_volatile_type))
       type = Dwarf::DIE(type.attribute(Dwarf::DW_AT_type));
    return type;
}

struct ArgPrint {
    Process &p;
    const StackFrame &frame;
    ArgPrint(Process &p_, const StackFrame &frame_)
        : p(p_), frame(frame_) {}
};

using namespace Dwarf;

struct RemoteValue {
    const Process &p;
    const Elf::Addr addr;
    const DIE type;
    std::vector<char> buf;
    std::string error;

    RemoteValue(const Process &p_, Elf::Addr addr_, bool isValue, DIE type_)
        : p(p_)
        , addr(addr_)
        , type(removeCV( std::move(type_)) ) {
      if (isValue) {
         buf.resize(sizeof addr_);
         memcpy(&buf[0], &addr_, sizeof addr_);
      } else {
         auto sizeAttr = type.attribute(DW_AT_byte_size);
         size_t size;
         if (sizeAttr.valid()) {
            size = uintmax_t(sizeAttr);
         } else if (type.tag() == DW_TAG_reference_type || type.tag() == DW_TAG_pointer_type) {
            size = sizeof (void *);
         } else {
            size = 0;
         }
         if (!size) {
            error = "<no size for type>";
         } else {
            buf.resize(size);
            auto rc = p.io->read(addr, size, &buf[0]);
            if (rc != size) {
               error = "<failed to read from remote>";
            }
         }
      }
   }
};

std::ostream &
operator << (std::ostream &os, const RemoteValue &rv)
{
    using namespace Dwarf;
    if (rv.addr == 0)
       return os << "(null)";

    IOFlagSave _(os);
    switch (rv.type.tag()) {
        case DW_TAG_base_type: {
            auto encoding = rv.type.attribute(DW_AT_encoding);
            if (!encoding.valid())
                throw (Exception() << "no encoding specified for base type");

            union {
               const int8_t *int8;
               const int16_t *int16;
               const int32_t *int32;
               const int64_t *int64;
               const float *float_;
               const double *double_;
               const void **voidp;
               const char *cp;
            } u;
            u.cp = &rv.buf[0];

            switch (uintmax_t(encoding)) {
                case DW_ATE_address:
                    os << *u.voidp;
                    break;
                case DW_ATE_boolean:
                    for (size_t i = 0;; ++i) {
                        if (i == rv.buf.size()) {
                            os << "false";
                            break;
                        }
                        if (rv.buf[i] != 0) {
                            os << "true";
                            break;
                        }
                    }
                    break;

                case DW_ATE_signed:
                case DW_ATE_signed_char:
                    switch (rv.buf.size()) {
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
                        default:
                            goto unknown;
                    }
                    break;

                case DW_ATE_unsigned:
                case DW_ATE_unsigned_char:
                    switch (rv.buf.size()) {
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
                            goto unknown;
                    }
                    break;
                case DW_ATE_float:
                    switch (rv.buf.size()) {
                       case sizeof(double):
                          os << *u.double_;
                          break;
                       case sizeof(float):
                          os << *u.float_;
                          break;
                    }
                    break;

                unknown:
                default:
                    os << "<unknown value type>";
                    break;
            }
            break;
        }
        case DW_TAG_reference_type:
        case DW_TAG_pointer_type: {
            auto ptr = *(Elf::Addr *)&rv.buf[0];
            os << (void *)ptr;
            auto reftype = removeCV(DIE(rv.type.attribute(DW_AT_type)));
            if (reftype) {
               if (reftype.name() == "char") {
                  std::string s = rv.p.io->readString(ptr);
                  os << " \"" << s << "\"";
               } else {
                  if (ptr == 0)
                     os << "->nullptr";
                  else
                     os << "->" << RemoteValue(rv.p, ptr, false, reftype);
                  break;
               }
            }
            break;
        }
        default:
            os << "<unprintable type " << rv.type.name() << ">";
    }
    return os;
}

std::ostream &
operator << (std::ostream &os, const ArgPrint &ap)
{
    ProcessLocation location = ap.frame.scopeIP(ap.p);
    if (!location.die() || !ap.p.context.options.doargs)
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
                        ExpressionStack fbstack;
                        addr = fbstack.eval(ap.p, attr, &ap.frame, location.elfReloc());
                        os << "=";
                        try {
                           os << RemoteValue(ap.p, addr, fbstack.isValue, type);
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

std::ostream &operator << (std::ostream &os, UnwindMechanism mech) {
   switch (mech) {
      case UnwindMechanism::MACHINEREGS: return os << "machine registers";
      case UnwindMechanism::DWARF: return os << "DWARF";
      case UnwindMechanism::FRAMEPOINTER: return os << "frame pointer";
      case UnwindMechanism::BAD_IP_RECOVERY: return os << "popped faulting IP";
      case UnwindMechanism::TRAMPOLINE: return os << "signal trampoline";
      case UnwindMechanism::LOGFILE: return os << "log file";
      case UnwindMechanism::INVALID: return os << "invalid";
   }
   abort();
}

std::ostream &
Process::dumpStackText(std::ostream &os, const ThreadStack &thread)
{
    os << std::dec;
    os << "thread: " << (void *)thread.info.ti_tid << ", lwp: "
       << thread.info.ti_lid << ", type: " << thread.info.ti_type << "\n";
    int frameNo = 0;
    for (auto &frame : thread.stack)
        dumpFrameText(os, frame, frameNo++);
    return os;
}

std::ostream &
Process::dumpFrameText(std::ostream &os, const StackFrame &frame, int frameNo)
{
    IOFlagSave _(os);
    PrintableFrame pframe(*this, frame);

    ProcessLocation location = frame.scopeIP(*this);
    std::vector<std::pair<std::string, int>> source;

    if (!context.options.nosrc)
        source = location.source();

    std::pair<std::string, int> src = source.size()
        ? source[0]
        : std::make_pair( "", std::numeric_limits<Elf::Addr>::max());

    if (!context.options.nodienames) {
        // inlining comes from DIEs with DW_TAG_inlined_subroutine - so no
        // point in trying this without DIE names
        for (auto i = pframe.inlined.rbegin(); i != pframe.inlined.rend(); ++i) {
           os << "#"
               << std::left << std::setw(2) << std::setfill(' ') << frameNo << " "
               << std::setw(ELF_BITS/4 + 2) << std::setfill(' ')
               << "inlined";
           os << " in ";
           buildDIEName(os, *i);
           if (!context.options.nosrc) {
               const auto &lineinfo = i->getUnit()->getLines();
               if (lineinfo) {
                  os << " at " << src.first << ":" << src.second;
                  auto &fileEnt = lineinfo->files[intmax_t(i->attribute(Dwarf::DW_AT_call_file))];
                  auto &dirname = lineinfo->directories[fileEnt.dirindex];
                  const auto &name = context.verbose ? dirname + "/" + fileEnt.name : fileEnt.name;
                  src = std::make_pair( name, intmax_t(i->attribute(Dwarf::DW_AT_call_line)));
                  os << "\n";
               }
           }
        }
    }

    os << "#"
        << std::left << std::setw(2) << std::setfill(' ') << frameNo << " "
        << std::right << "0x" << std::hex << std::setw(ELF_BITS/4) << std::setfill('0')
        << frame.rawIP() << std::dec;

    if (location.inObject()) {
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
            << "(" << ArgPrint(*this, frame) << ")";

        if (pframe.functionOffset != std::numeric_limits<Elf::Addr>::max())
            os << "+" << pframe.functionOffset;
        os << " in " << stringify(*location.elf()->io);
        if (context.verbose)
           os << "@0x" << std::hex << frame.rawIP() - location.elfReloc() << std::dec;
        if (src.first != "")
           os << " at " << src.first << ":" << std::dec << src.second;
    } else {
        os << " no information for frame";
    }
    if (context.verbose)
       os << " via " << frame.mechanism;
    os << "\n";
    return os;
}

void
Process::addElfObject(std::string_view name, const Elf::Object::sptr &obj, Elf::Addr load)
{
    Elf::BuildID bid;
    try {
        auto bidElf = obj ? obj : std::make_shared<Elf::Object>(context, io->view( "in-memory elf object", load, 0x4000), false);
        bid = bidElf->getBuildID();
    }
    catch (const Exception &ex) {
        *context.debug << "failed to read build id from memory image\n";
    }

    objects.emplace(std::make_pair(load, MappedObject{ name, bid, obj }));
    if (context.verbose >= 2) {
        IOFlagSave _(*context.debug);
        *context.debug << "object " << name;
        if (bid)
            *context.debug << " with in-process build ID " << bid;
        *context.debug << " loaded at address " << std::hex << load << std::dec << std::endl;
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
                *context.debug << "calculated load address for executable from process entrypoint ("
                << std::hex << loadAddr << ") does not match link map (" << map.l_addr
                << "). Trusting link-map\n" << std::dec;
            }
            addElfObject("(exe)", execImage, map.l_addr);
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
            addElfObject(path, nullptr, Elf::Addr(map.l_addr));
        }
        catch (const std::exception &e) {
            if (context.debug)
               *context.debug << "warning: can't load text for '" << path << "' at " <<
            (void *)mapAddr << "/" << (void *)map.l_addr << ": " << e.what() << "\n";
            continue;
        }
    }
}

Elf::Addr
Process::findRDebugAddr()
{
   // We should really have already worked out dt_debug, as we should have
   // found the program headers for the loaded program, and gone through them
   // to find DT_DEBUG in processAUXV already. Just in case things go wrong, we
   // try a few other approaches too.

    /*
     * Calculate the address the executable was loaded at - we know the entry
     * supplied by the kernel, and also the executable's desired entrypoint -
     * the difference is the load address.
     */

    if (dt_debug == 0) {
       Elf::Off loadAddr = entry - execImage->getHeader().e_entry;

       // ITerate over the PT_DYNAMIC segment of the loaded executable. (We should
       // not get here, as we should have found the program headers in the AT_PHDR
       // auxv entry, and done this already
       for (auto &segment : execImage->getSegments(PT_DYNAMIC)) {
           // Read from the process, not the executable - the linker will have updated the content.
           auto dynReader = io->view("PT_DYNAMIC segment", segment.p_vaddr + loadAddr, segment.p_filesz);
           ReaderArray<Elf::Dyn> dynamic(*dynReader);
           for (auto &dyn : dynamic) {
               if (dyn.d_tag == DT_DEBUG && dyn.d_un.d_ptr != 0) {
                   if (context.verbose)
                       *context.debug << "found rdebugaddr via DT_DEBUG at " << dyn.d_un.d_ptr << "\n";
                   dt_debug = dyn.d_un.d_ptr;
                   break;
               }
           }
       }
    }

    /*
     * If there's no DT_DEBUG, we've probably got someone executing a shared
     * library, which doesn't have an _r_debug symbol. Use the address of
     * _r_debug in the interpreter
     */
    if (dt_debug == 0 && interpBase && execImage->getInterpreter() != "") {
        try {
            addElfObject(execImage->getInterpreter(), nullptr, interpBase);
            dt_debug = resolveSymbol("_r_debug", false,
                  [this](const std::string_view name) {
                      return execImage->getInterpreter() == name;
                  });
        }
        catch (...) {
        }
    }
    return dt_debug;
}

std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *>
Process::findSegment(Elf::Addr addr)
{
    auto it = objects.lower_bound(addr);
    if (it != objects.begin()) {
       --it;
       auto obj = it->second.object(context);
       if (it->first + obj->endVA() >= addr) {
           auto segment = obj->getSegmentForAddress(addr - it->first);
           if (segment)
               return std::make_tuple(it->first, obj, segment);
       }
    }
    return std::tuple<Elf::Addr, Elf::Object::sptr, const Elf::Phdr *>();
}

std::tuple<Elf::Object::sptr, Elf::Addr, Elf::Sym>
Process::resolveSymbolDetail(const char *name, bool includeDebug,
        std::function<bool(std::string_view)> match)
{
    for (auto &loaded : objects) {
        if (!match(loaded.second.name()))
           continue;
        auto obj = loaded.second.object(context);
        auto [sym,idx] = obj->findDynamicSymbol(name);
        if (sym.st_shndx != SHN_UNDEF)
           return std::make_tuple(obj, loaded.first, sym);
        if (includeDebug) {
           auto [sym, idx] = loaded.second.object(context)->findDebugSymbol(name);
           if (sym.st_shndx != SHN_UNDEF)
              return std::make_tuple(obj, loaded.first, sym);
        }
    }
    throw (Exception() << "symbol " << name << " not found");
}

Elf::Addr
Process::resolveSymbol(const char *name, bool includeDebug,
        std::function<bool(std::string_view)> match)
{
    auto info = resolveSymbolDetail(name, includeDebug, match);
    return std::get<1>(info) + std::get<2>(info).st_value;

}

Process::~Process()
{
    // don't leave the VDSO in the cache - a new copy will be entered for a new
    // process.
    context.flush(vdsoImage);
    td_ta_delete(agent);
}

void
ThreadStack::unwind(Process &p, Elf::CoreRegisters &regs)
{
    stack.clear();
    stack.reserve(20);

#ifdef __aarch64__
    // for ARM, if we see __kernel_rt_sigreturn on the stack, we have a signal
    // stack frame
    Elf::Addr trampoline = 0;
    if (p.vdsoImage) {
       auto [sigreturnSym,idx] = p.vdsoImage->findDynamicSymbol("__kernel_rt_sigreturn");
       if (sigreturnSym.st_shndx != SHN_UNDEF) {
          trampoline = sigreturnSym.st_value + p.vdsoBase;
       }
    }
#endif

    try {
        stack.emplace_back(UnwindMechanism::MACHINEREGS, regs);

        // Set up the first frame using the machine context registers
        stack.front().setCoreRegs(regs);

        for (int frameCount = 0; frameCount < p.context.options.maxframes; frameCount++) {
            auto &prev = stack.back();

            try {
                auto maybeNewRegs = prev.unwind(p);
                if (!maybeNewRegs)
                    break;
                auto &newRegs = *maybeNewRegs;
                stack.emplace_back(UnwindMechanism::DWARF, newRegs);
#ifdef __aarch64__
                auto &cur = stack.back();
                if (newRegs.pc == trampoline)
                    cur.isSignalTrampoline = true;
#endif
            }
            catch (const std::exception &ex) {

                if (p.context.verbose > 2)
                    *p.context.debug << "failed to unwind frame with DWARF: "
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
                // have done had we fallen down to frame pointer unwinding, but
                // we'd need to be executing an instruction in a piece of
                // runtime-generated code, or something else that wasn't in a
                // normal ELF phdr, so it seems more likely this is the best
                // thing to do.
                //
                // For ARM, the concept is the same, but we look at the link
                // register rather than a pushd return address


                if (stack.size() == 1 || stack[stack.size() - 2].isSignalTrampoline) {
                    ProcessLocation badip = { p, IP(prev.regs) };
                    if (!badip.inObject() || (badip.codeloc->phdr().p_flags & PF_X) == 0) {
                        auto newRegs = prev.regs; // start with a copy of prev frames regs.
#if defined(__amd64__) || defined(__i386__)
                        // get stack pointer in the current frame, and read content of TOS
                        auto sp = SP(prev.regs);
                        Elf::Addr ip;
                        auto in = p.io->read(sp, sizeof ip, (char *)&ip);
                        if (in == sizeof ip) {
                            SP(newRegs) = sp + sizeof ip;
                            IP(newRegs) = ip;             // .. insn pointer.
                            stack.emplace_back(UnwindMechanism::BAD_IP_RECOVERY, newRegs);
                            continue;
                        }

#elif defined(__aarch64__)
                        newRegs.pc = prev.regs.regs[30]; // Copy old link register into new instruction pointer.
                        stack.emplace_back(UnwindMechanism::BAD_IP_RECOVERY, newRegs);
                        continue;
#endif
                    }
                }
#if defined(__aarch64__)
                // Deal with unwinding through an ARM signal handler
                if (trampoline && trampoline == prev.rawIP()) {
                    // the stack pointer is pointing directly at rt_sigframe. This is
                    // as per arch/arm64/kernel/signal.c
                    struct rt_sigframe {
                       siginfo_t si;
                       ucontext_t uc;
                    };
                    auto sigframe = p.io->readObj<rt_sigframe>(prev.regs.sp);
                    Elf::CoreRegisters newRegs;
                    for (int i = 0; i < 31; ++i)
                       newRegs.regs[i] = sigframe.uc.uc_mcontext.regs[i];
                    newRegs.sp = sigframe.uc.uc_mcontext.sp;
                    newRegs.pc = sigframe.uc.uc_mcontext.pc;
                    stack.emplace_back(UnwindMechanism::TRAMPOLINE, newRegs);
                    continue;
                }
#endif
#if defined(__i386__)
                // Deal with signal trampolines for i386
                Elf::Addr reloc;
                const Elf::Phdr *segment;
                Elf::Object::sptr obj;
                std::tie(reloc, obj, segment) = p.findSegment(prev.rawIP());
                if (obj) {
                    Elf::Addr sigContextAddr = 0;
                    auto objip = prev.rawIP() - reloc;
                    // Find the gregset on the stack - it differs depending on
                    // whether this is realtime or "classic" frame
                    auto [restoreSym,idx] = obj->findDebugSymbol("__restore");
                    if (restoreSym.st_shndx != SHN_UNDEF && objip == restoreSym.st_value)
                        sigContextAddr = SP(prev.regs) + 4;
                    else {
                        auto [restoreRtSym,idx] = obj->findDebugSymbol("__restore_rt");
                        if (restoreRtSym.st_shndx != SHN_UNDEF && objip == restoreRtSym.st_value)
                            sigContextAddr = p.io->readObj<Elf::Addr>(SP(prev.regs) + 8) + 20;
                    }
                    if (sigContextAddr != 0) {
                       // This mapping is based on DWARF regnos, and ucontext.h
                       gregset_t regs;
                       p.io->readObj(sigContextAddr, &regs);
                       Elf::CoreRegisters core;
                       gregset2core(core, regs);
                       stack.emplace_back(UnwindMechanism::TRAMPOLINE, core);
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
                       Elf::CoreRegisters newRegs = prev.regs;
                       SP(newRegs) = oldBp + ELF_BYTES * 2;
                       BP(newRegs) = newBp;
                       IP(newRegs) = newIp;
                       stack.emplace_back(UnwindMechanism::FRAMEPOINTER, newRegs);
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
        if (p.context.debug)
           *p.context.debug << "warning: exception unwinding stack: " << ex.what() << std::endl;
    }
}

std::shared_ptr<Process>
Process::load(Context &context, Elf::Object::sptr exec, std::string id) {
    pid_t pid;
    auto [ ptr, ec ] = std::from_chars(id.data(), id.data() + id.size(), pid);

    std::shared_ptr<Process> proc;
    if (ec == std::errc() && ptr == id.data() + id.size()) {
       if (kill(pid, 0) != 0)
          throw Exception() << "process " << pid << ": " << strerror(errno);
       proc = std::make_shared<LiveProcess>(context, exec, pid);
    } else {
       // don't use imagecache for cores. We don't want to mmap them (they can
       // be enormous, esp. from a leaky process), use loadFile and a caching
       // reader on the underlying file instead.
       auto core = std::make_shared<Elf::Object>(context, context.loadFile(id));
       if (core->getHeader().e_type != ET_CORE)
          return nullptr; // image is ELF, but not a core - just return null
       proc = std::make_shared<CoreProcess>(context, exec, core);
    }
    proc->load();
    return proc;
}

std::list<ThreadStack>
Process::getStacks() {
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
    listThreads([this, &threadStacks, &tracedLwps] (
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
            threadStacks.back().unwind(*this, regs);
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
    listLWPs([this, &threadStacks, &tracedLwps](lwpid_t lwpid) {
        if (tracedLwps.find(lwpid) == tracedLwps.end()) {
            threadStacks.push_back(ThreadStack());
            threadStacks.back().info.ti_lid = lwpid;
            Elf::CoreRegisters regs;
            this->getRegset<Elf::CoreRegisters, NT_PRSTATUS>(lwpid,  regs);
            threadStacks.back().unwind(*this, regs);
        }
    });

    /*
     * if we don't need to print arguments to functions, we now have the full
     * backtrace and don't need to read anything more from the process.
     * Everything else is just parsing debug data, so we can resume now.
     */
    if (!context.options.doargs)
        processSuspender.clear();
    return threadStacks;
}

std::ostream &
operator << (std::ostream &os, WaitStatus ws) {
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

std::ostream &operator << (std::ostream &os, const SigInfo &sip) {
   const auto si = sip.si;

   static std::map<int, std::map<int, const char *>> codes {
         { SIGSEGV,  {
                     { SEGV_MAPERR, "address not mapped to object" },
                        { SEGV_ACCERR, "invalid permissions for mapped object" },
                        { SEGV_BNDERR, "address failed bouds checks" },
                        { SEGV_ACCADI, "ADI not enabled" },
                        { SEGV_ADIDERR, "disrupting MCD error" },
                        { SEGV_ADIPERR, "precise MCD exception" },
                        { SEGV_MTEAERR, "asynchronous ARM MTE error" },
                  } },
         { 0,     {
                     { SI_USER, "sent by kill/sigsend/raise" },
                     { SI_KERNEL, "sent by kernel" },
                     { SI_QUEUE, "sent by sigqueue" },
                     { SI_TIMER, "sent by timer expiration" },
                     { SI_MESGQ, "sent by real time mesq state change" },
                     { SI_ASYNCIO, "sent by AIO completion" },
                     { SI_SIGIO, "sent by queued SIGIO" },
                     { SI_TKILL, "sent by tkill syscall" },
                     { SI_DETHREAD, "sent by execve killing subsidiary threads" },
                     { SI_ASYNCNL, "sent by glibc async name lookup completion" },
                     { POLL_IN, "data input available" },
                     { POLL_OUT, "output buffers available" },
                     { POLL_MSG, "input message available" },
                     { POLL_ERR, "I/O error" },
                     { POLL_PRI, "high priority input available" },
                     { POLL_HUP, "device disconnected" },
                  } },
         { SIGILL, {
                      { ILL_ILLOPC, "illegal opcode" },
                      { ILL_ILLOPN, "illegal operand" },
                      { ILL_ILLADR, "illegal address mode" },
                      { ILL_ILLTRP, "illegal trap" },
                      { ILL_PRVOPC, "privileged opcode" },
                      { ILL_PRVREG, "privileged register" },
                      { ILL_COPROC, "coprocessor error" },
                      { ILL_BADSTK, "internal stack error" },
                      { ILL_BADIADDR, "unimplemented instruction address" },
                      /*
                      { __ILL_BREAK, "illegal break" },
                      { __ILL_BNDMOD, "bundle-pudate (modification) in proress" }
                      */
                   } },
         { SIGFPE, {
                      { FPE_INTDIV, "integer divide by zero" },
                      { FPE_INTOVF, "integer overflow" },
                      { FPE_FLTDIV, "floating point divide by zero" },
                      { FPE_FLTOVF, "floating point overflow" },
                      { FPE_FLTUND, "floating point underflow" },
                      { FPE_FLTRES, "floating point inexact result" },
                      { FPE_FLTINV, "floating point invalid operation" },
                      { FPE_FLTSUB, "subscript out of range" },
                      /*
                      { __FPE_DECOVF, "decimal overflow" },
                      { __FPE_DECDIV, "decimal division" },
                      { __FPE_DECERR, "packed decimal error" },
                      { __FPE_INVASC, "invalid ASCII digit" },
                      { __FPE_INVDEC, "invalid decimal digit" },
                      */
                      { FPE_FLTUNK, "undiagnosed floating point exception" },
                      { FPE_CONDTRAP, "trap condition" },
                   } },
         { SIGBUS, {
                      { BUS_ADRALN, "invalid address alignment" },
                      { BUS_ADRERR, "non-existent physical address" },
                      { BUS_OBJERR, "object specific hardware error" },
                      { BUS_MCEERR_AR, "hardware memory error consumed on a machine check: action required" },
                      { BUS_MCEERR_AO, "hardware memory error consumed on a machine check: action optional" },
                   }
         },
         { SIGTRAP, {
                       { TRAP_BRKPT, "process breakpoint" },
                       { TRAP_TRACE, "process trace trap" },
                       { TRAP_BRANCH, "process taken branch trap" },
                       { TRAP_HWBKPT, "hardware breakpoint/watchpoint" },
                       { TRAP_UNK, "undiagnosed trap" },
                       /*
                       { TRAP_PERF, "perf event with sigtrap=1" },
                       */
                    }
         },
         {  SIGSYS, {
                       /*
                       { SYS_SECCOMP, "seccomp triggered" },
                       { SYS_USER_DISPATCH, "syscall user dispatch triggered" }
                       */
                    }
         },
   };

   os << sigdescr_np( si.si_signo )
      << " SIG" << sigabbrev_np( si.si_signo )
      << ", si_code " << si.si_code;

   auto codesforsig = codes.find( si.si_signo );
   if (codesforsig == codes.end()) {
      codesforsig = codes.find( 0 );
   }

   if (codesforsig != codes.end()) {
      auto code = codesforsig->second.find( si.si_code );
      if (code != codesforsig->second.end())
            os << " - " << code->second;
   }

   switch (si.si_signo) {
      case SIGILL:
      case SIGFPE:
      case SIGBUS:
      case SIGTRAP:
#ifdef SIGEMT
      case SIGEMT:
#endif
      case SIGSEGV: {
         os << ", fault address " << std::hex << si.si_addr << std::dec;
         break;
      }


   }
   return os;
}}

std::ostream &
operator << (std::ostream &os, const JSON<Procman::StackFrame, Procman::Process *> &jt)
{
    auto &frame =jt.object;
    Procman::ProcessLocation location = frame.scopeIP(*jt.context);
    Procman::PrintableFrame pframe(*jt.context, frame);

    JObject jo(os);
    jo
        .field("ip", frame.rawIP())
        .field("offset", pframe.functionOffset)
        .field("trampoline", frame.isSignalTrampoline)
        .field("die", pframe.dieName)
        .field("loadaddr", location.elfReloc())
        ;

    const auto &sym = location.symbol();
    if (sym)
        jo.field("symbol", *sym);
    else
        jo.field("symbol", JsonNull());

    jo.field("source", location.source());

    return jo;
}

}
