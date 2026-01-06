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

#include "libpstack/arch.h"
#include "libpstack/dwarf.h"
#include "libpstack/proc.h"
#include "libpstack/stringify.h"
#include "libpstack/ioflag.h"

#if defined(__amd64__)
#define BP(regs) (regs.user.rbp)
#define SP(regs) (regs.user.rsp)
#define IP(regs) (regs.user.rip)
#elif defined(__i386__)
#define BP(regs) (regs.user.ebp)
#define SP(regs) (regs.user.esp)
#define IP(regs) (regs.user.eip)
#elif defined(__aarch64__)
#define IP(regs) (regs.user.pc)
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
operator << (std::ostream &os, const JSON<Procman::Lwp, Procman::Process *> &ts)
{
   JObject jo(os);
   auto &lwp = ts.object;

   if (ts.object.threadInfo.has_value()) {
      auto &ti = *lwp.threadInfo;
      jo
         .field("ti_tid", ti.ti_tid)
         .field("ti_type", ti.ti_type)
         .field("ti_pri", ti.ti_pri)
         ;
   }
   return jo
      .field("ti_lid", lwp.id)
      .field("name", *lwp.name)
      .field("ti_stack", lwp.stack, ts.context);
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
gregset2user(user_regs_struct &core, const gregset_t greg) {
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
    : agent(nullptr)
    , execImage(std::move(exec))
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
    try {
        findRDebugAddr();
        bool isStatic = dt_debug == 0 || dt_debug == Elf::Addr(-1);

        if (isStatic) {
            if (execImage)
                addElfObject("", execImage, 0);
        } else {
            loadSharedObjects(dt_debug);
        }
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
    return context.findDwarf(elf);
}


struct AuxType {
   int type;
   AuxType(int type) : type(type) {}
};

std::ostream &operator << (std::ostream &os, AuxType auxtype) {
#define AUX_TYPE(t, v) if (auxtype.type == t) return os << #t;
#include "libpstack/elf/auxv.h"
   return os << "unknown type " << auxtype.type;
#undef AUX_TYPE
}

Elf::Addr
Process::extractDtDebugFromDynamicSegment(const Elf::Phdr &phdr, Elf::Addr loadAddr, const char *loc) {
    auto dynReader = io->view("PT_DYNAMIC segment", phdr.p_vaddr + loadAddr, phdr.p_filesz);
    ReaderArray<Elf::Dyn> dynamic(*dynReader);
    for (auto &dyn : dynamic) {
        if (dyn.d_tag == DT_DEBUG && dyn.d_un.d_ptr != 0) {
            if (context.verbose)
                *context.debug << "found rdebugaddr via DT_DEBUG at "
                   << std::hex << dyn.d_un.d_ptr << std::dec << " in " << loc << "\n";
            return dyn.d_un.d_ptr;
        }
    }
    return 0;
}

void
Process::processAUXV(const Reader &auxio)
{
    std::string exeName;
    Elf::Addr phOff = 0;
    size_t phNum = 0;
    for (auto &aux : ReaderArray<Elf::auxv_t>(auxio)) {
        Elf::Addr hdr = aux.a_un.a_val;
        if (context.verbose > 2)
            *context.debug << "auxv: " << AuxType(aux.a_type) << ": " << hdr << std::endl;
        if (aux.a_type == AT_NULL)
           break;
        switch (aux.a_type) {
            case AT_ENTRY: {
                // this provides a reference for relocating the executable when
                // compared to the entrypoint in the image.
                entry = hdr;
                break;
            }
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
                   if (context.verbose > 1)
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

    if (phOff != 0 && phNum != 0) {
        // If we have phdrs, process them. Use PT_PHDR to find the relocation ofset
        // between the phOff and the virtual addresses in the executable image.
        auto view = io->view("phdrs", phOff, sizeof (Elf::Phdr) * phNum);
        ReaderArray<Elf::Phdr> headers { *view };
        std::optional<Elf::Phdr> ptDynamic;

        std::vector<Elf::Addr> notes;
        try {
            for ( auto phdr : headers ) {
                switch (phdr.p_type) {
                    case PT_PHDR:
                        // that's the diff between the va's in the process vs the image.
                        execBase = phOff - phdr.p_vaddr;
                        break;
                    case PT_NOTE:
                        notes.push_back(phdr.p_vaddr);
                        break;
                    case PT_DYNAMIC:
                        ptDynamic = phdr;
                        break;
                }
            }
        }
        catch (const Exception &ex) {
            // We may not have a full image of the phdrs.
        }

        if (ptDynamic && dt_debug == 0)
            dt_debug = extractDtDebugFromDynamicSegment(*ptDynamic, execBase, "aux vector");

        // Find the executable image
        if (!execImage) {
            // search for a GNU_BUILD_ID note in the notes.
            for ( auto noteOff : notes) {
                auto noteVa = noteOff + execBase;
                auto n = io->readObj<Elf::Note>( noteOff + execBase );
                if (n.n_type != Elf::GNU_BUILD_ID)
                    continue;
                std::vector<char> name(n.n_namesz);
                io->read(noteVa + sizeof n, name.size(), name.data());
                if (name[n.n_namesz - 1] == 0)
                    name.resize(name.size() - 1);
                if (std::string_view(name.data(), name.size()) != "GNU")
                    continue;

                std::vector<uint8_t> data;
                data.resize(n.n_descsz);
                io->read(noteVa + sizeof n + 4, n.n_descsz, (char *)data.data());
                if (context.verbose)
                    *context.debug << "build ID From AT_PHDR: " << Elf::BuildID(data) << "\n";
                execImage = context.findImage(Elf::BuildID{data});
                break;
            }
        }
    }

    if (!execImage && exeName != "")
       execImage = context.findImage(exeName);
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
      case UnwindMechanism::LINKREG: return os << "link register";
      case UnwindMechanism::INVALID: return os << "invalid";
   }
   abort();
}

std::ostream &
Process::dumpStackText(std::ostream &os, const Lwp &lwp)
{
    os << std::dec;
    if (lwp.threadInfo.has_value()) {
       auto &ti = *lwp.threadInfo;
       os << "thread: " << (void *)ti.ti_tid
          << ", type: " << ti.ti_type
          << ", ";
    }
    os << "lwp: " << lwp.id;
    if (lwp.name.has_value())
       os << ", name: " << *lwp.name;
    os << "\n";

    int frameNo = 0;
    for (auto &frame : lwp.stack)
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
       // this is not a fatal problem - ELF headers may or may not be present in the core.
       if (context.verbose > 1)
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
            if (execImage) {
                if (execBase == 0) {
                    execBase = entry - execImage->getHeader().e_entry;
                }
                if (execBase != map.l_addr) {
                    *context.debug << "calculated load address for executable from process entrypoint ("
                        << std::hex << execBase << ") does not match link map (" << map.l_addr
                        << "). Trusting link-map\n" << std::dec;
                }
                addElfObject("(exe)", execImage, map.l_addr);
            }
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
    /*
     * We should have already worked out dt_debug by now, as we should have
     * found the program headers for the loaded program when running
     * processAUXV, and gone through them to find DT_DEBUG.
     *
     * Just in case things went wrong, we try a few other approaches to locate
     * DT_DEBUG (for example, ELF images don't *have* to have a DYNAMIC segment
     * to be executable)
     *
     * Calculate the address the executable was loaded at - we know the entry
     * supplied by the kernel, and also the executable's desired entrypoint -
     * the difference is the load address.
     */

    if (dt_debug == 0 && execImage) {
        // Iterate over the PT_DYNAMIC segment of the loaded executable. (We
        // should not get here, as we should have found the program headers in
        // the AT_PHDR auxv entry, and done this already
        Elf::Off loadAddr = entry - execImage->getHeader().e_entry;
        for (auto &segment : execImage->getSegments(PT_DYNAMIC)) {
            dt_debug = extractDtDebugFromDynamicSegment(segment, loadAddr, "exec image");
        }
    }

    /*
     * If there's no DT_DEBUG, we've probably got someone executing a shared
     * library, which doesn't have an _r_debug symbol. Use the address of
     * _r_debug in the interpreter
     */
    if (dt_debug == 0 && execImage && interpBase && execImage->getInterpreter() != "") {
        try {
            addElfObject(execImage->getInterpreter(), nullptr, interpBase);
            dt_debug = resolveSymbol("_r_debug", false,
                    [this](const std::string_view name) {
                    return execImage->getInterpreter() == name;
                    });
            if (dt_debug != 0 && context.debug) {
                *context.debug << "found DT_DEBUG using address of _r_debug symbol\n";
            }

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
       if (obj && it->first + obj->endVA() >= addr) {
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
        if (!obj)
            continue;
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
Lwp::unwind(Process &p, const CoreRegisters &regs)
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
            trampoline = sigreturnSym.st_value + p.getVdsoBase();
        }
    }
#endif

    stack.emplace_back(UnwindMechanism::MACHINEREGS, regs);

    for (int frameCount = 0; frameCount < p.context.options.maxframes; frameCount++) {
        auto &prev = stack.back();

        try {
            auto maybeNewRegs = prev.unwind(p);
            if (!maybeNewRegs)
                break;
            // XXX: the emplace_back below invalidates prev
            bool isSignal = prev.isSignalTrampoline;
            auto &newRegs = *maybeNewRegs;
            stack.emplace_back(UnwindMechanism::DWARF, newRegs);
            if (isSignal) {
                stack.back().unwoundFromTrampoline = true;
            }
#ifdef __aarch64__
            auto &cur = stack.back();
            if (newRegs.user.pc == trampoline)
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

            if (prev.mechanism == UnwindMechanism::MACHINEREGS
                    || prev.mechanism == UnwindMechanism::TRAMPOLINE
                    || prev.unwoundFromTrampoline ) {
                ProcessLocation badip { p, Elf::Addr(IP(prev.regs)) };
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
                    // Copy old link register into new instruction pointer.
                    newRegs.user.pc = prev.regs.user.regs[30];
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
                auto sigframe = p.io->readObj<rt_sigframe>(prev.regs.user.sp);
                CoreRegisters newRegs;
                for (int i = 0; i < 31; ++i)
                    newRegs.user.regs[i] = sigframe.uc.uc_mcontext.regs[i];
                newRegs.user.sp = sigframe.uc.uc_mcontext.sp;
                newRegs.user.pc = sigframe.uc.uc_mcontext.pc;
                // Copy any extension registers. (For now, just the FP/SIMD set.)
                const unsigned char *rawctx = sigframe.uc.uc_mcontext.__reserved;
                const struct _aarch64_ctx *aarchctx;
                for (bool done = false; !done; rawctx += aarchctx->size) {
                    aarchctx = reinterpret_cast<const _aarch64_ctx *>(rawctx);
                    switch (aarchctx->magic) {
                        case 0:
                            done = true;
                            break;
                        case FPSIMD_MAGIC: {
                            newRegs.fpsimd = *reinterpret_cast<const user_fpsimd_struct *>(rawctx + aarchctx->size);
                            break;
                        }
                        default:
                            if (p.context.debug && p.context.verbose > 1) {
                                *p.context.debug
                                    << "ignoring unrecognized AARCH64 register set in signal frame: "
                                    << "magic: " << reinterpret_cast<void *>(aarchctx->magic)
                                    << ", len " << aarchctx->size <<"\n";
                            }
                            break;
                    }
                }

                stack.emplace_back(UnwindMechanism::TRAMPOLINE, newRegs);
                continue;
            }
            // last ditch effort for ARM is to just replace the PC with the
            // LR - this is useful for PLT entries, for example.
            if (prev.regs.user.regs[30] != prev.regs.user.pc) {
                CoreRegisters newRegs = prev.regs;
                newRegs.user.pc = newRegs.user.regs[30];
                stack.emplace_back(UnwindMechanism::LINKREG, newRegs);
                continue;
            }

#endif
#if defined(__i386__) || defined(__amd64__)
            auto [ reloc, obj, segment ] = p.findSegment(prev.rawIP());
#if defined(__i386__)
            // Deal with signal trampolines for i386
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
                    CoreRegisters core;
                    gregset2user(core.user, regs);
                    stack.emplace_back(UnwindMechanism::TRAMPOLINE, core);
                    continue;
                }
            }
#endif
            // frame-pointer unwinding.
            // Use ebp/rbp to find return address and saved BP.
            // Restore those, and the stack pointer itself.
            //
            // We skip this if the instruction pointer is zero - we hope
            // we'd have resolved null-pointer calls above, and if we find
            // a 0 ip on the call stack, it's a good indication the
            // unwinding is finished.
            if (prev.rawIP() != 0) {
                Elf::Addr oldBp = BP(prev.regs);
                if (oldBp == 0) {
                    // null base pointer means we're done.
                    break;
                }
                auto newIp = p.io->readObj<Elf::Addr> (oldBp + ELF_BYTES);
                auto newBp = p.io->readObj<Elf::Addr>(oldBp);
                auto [ _1, _2, segment ] = p.findSegment(newIp);

                // If the value we got for the instruction pointer is in an
                // executable segment, then consider that good enough
                // evidence that we were probably successful with our
                // frame-pointer based unwind. This is the last chance
                // anyway, o worst case is you get some noisy junk stack
                // frames at the end.

                if (segment && segment->p_flags & PF_X) {
                    CoreRegisters newRegs = prev.regs;
                    SP(newRegs) = oldBp + ELF_BYTES * 2;
                    IP(newRegs) = newIp;
                    BP(newRegs) = newBp;
                    stack.back().cfa = SP(newRegs);
                    stack.emplace_back(UnwindMechanism::FRAMEPOINTER, newRegs);
                    continue;
                }
            }
#endif
            // We can't unwind this frame: give up, and return what we've
            // already unwound.
            *p.context.debug << "warning: stack unwinding terminated with error: "
               << ex.what() << "\n";
            break;
        }
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

std::optional<std::string>
Process::getTaskName([[maybe_unused]] lwpid_t lwp) const {
   return std::nullopt;
}

Stacks
Process::getStacks() {
    Stacks stacks;
    StopProcess processSuspender(this);

    /*
     * Find LWPs, the kernel scheduled entities.
     */
    listLWPs([this, &stacks ](lwpid_t lwpid) {
          Lwp lwp;
          lwp.id = lwpid;
          try {
             lwp.unwind(*this, getCoreRegs(lwpid));
             lwp.name = getTaskName(lwpid);
             stacks.emplace(std::make_pair(lwpid, std::move(lwp)));
          }
          catch (const Exception &ex) {
            *context.debug << "failed to unwind stack for  " << lwpid << ": " << ex.what() << "\n";
          }
       });

    /*
     * Use the thread db to find at least the thread ids for each lwp. We
     * assume that we are in the modern linux 1:1 threading world, and punt on
     * anything more sophisticated here.
     */
    if (agent) {
       listThreads([this, &stacks] ( const td_thrhandle_t *thr) {
          td_thrinfo_t info;
          if (td_thr_get_info(thr, &info) == TD_OK) {
             auto stack = stacks.find(info.ti_lid);
             if (stack != stacks.end()) {
                stack->second.threadInfo = info;
             } else {
                *context.debug << "warning: no LWP for thread " << info.ti_tid << ", alleged LWP id " << info.ti_lid << "\n";
             }
          }
       });
    }
    return stacks;
}

CoreRegisters
Process::getCoreRegs(lwpid_t lwp) {
   CoreRegisters coreRegs;
   getRegset<user_regs_struct, NT_PRSTATUS>(lwp, coreRegs.user);
#ifdef __aarch64__
   getRegset<user_fpsimd_struct, NT_FPREGSET>(lwp, coreRegs.fpsimd);
#elif defined(__x86_64__)
   getRegset<user_fpregs_struct, NT_FPREGSET>(lwp, coreRegs.fp);
#elif defined(__i386__)
   getRegset<user_fpxregs_struct, NT_PRXFPREG>(lwp, coreRegs.fpx);
#endif
   return coreRegs;
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
#ifdef SEGV_BNDERR
                        { SEGV_BNDERR, "address failed bouds checks" },
#endif
#ifdef SEGV_ACCADI
                        { SEGV_ACCADI, "ADI not enabled" },
#endif
#ifdef SEGV_ADIDERR
                        { SEGV_ADIDERR, "disrupting MCD error" },
#endif
#ifdef SEGV_ADIPERR
                        { SEGV_ADIPERR, "precise MCD exception" },
#endif
#ifdef SEGV_MTEAERR
                        { SEGV_MTEAERR, "asynchronous ARM MTE error" },
#endif
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
#ifdef SI_DETHREAD
                     { SI_DETHREAD, "sent by execve killing subsidiary threads" },
#endif
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
#ifdef ILL_BADIADDR
                      { ILL_BADIADDR, "unimplemented instruction address" },
#endif
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
#ifdef FPE_FLTUNK
                      { FPE_FLTUNK, "undiagnosed floating point exception" },
#endif
#ifdef FPE_CONDTRAP
                      { FPE_CONDTRAP, "trap condition" },
#endif
                   } },
         { SIGBUS, {
                      { BUS_ADRALN, "invalid address alignment" },
                      { BUS_ADRERR, "non-existent physical address" },
                      { BUS_OBJERR, "object specific hardware error" },
#ifdef BUS_MCEERR_AR
                      { BUS_MCEERR_AR, "hardware memory error consumed on a machine check: action required" },
#endif
#ifdef BUS_MCEERR_AO
                      { BUS_MCEERR_AO, "hardware memory error consumed on a machine check: action optional" },
#endif
                   }
         },
         { SIGTRAP, {
                       { TRAP_BRKPT, "process breakpoint" },
                       { TRAP_TRACE, "process trace trap" },
#ifdef TRAP_BRANCH
                       { TRAP_BRANCH, "process taken branch trap" },
#endif
#ifdef TRAP_HWBKPT
                       { TRAP_HWBKPT, "hardware breakpoint/watchpoint" },
#endif
#ifdef TRAP_UNK
                       { TRAP_UNK, "undiagnosed trap" },
#endif
#ifdef TRAP_PERF
                       { TRAP_PERF, "perf event with sigtrap=1" },
#endif
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

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 32))
    #define HAVE_SIGXXX_NP
#endif

   os
#ifdef HAVE_SIGXX_NP
      << sigdescr_np( si.si_signo )
      << " SIG" << sigabbrev_np( si.si_signo )
#else
      << "si_signo " << si.si_signo
#endif
      << ", si_code " << si.si_code
      << ", si_pid " << si.si_pid
      << ", si_fd " << si.si_fd
      << ", si_addr " << si.si_addr
        ;

   auto codesforsig = codes.find( si.si_signo );
   if (codesforsig == codes.end()) {
      codesforsig = codes.find( 0 );
   }

   if (codesforsig != codes.end()) {
      auto code = codesforsig->second.find( si.si_code );
      if (code != codesforsig->second.end())
            os << " - " << code->second;
   }
   return os;
}}

std::ostream &
operator << (std::ostream &os, const JSON<Procman::StackFrame, Procman::Process *> &jt)
{
    auto &frame =jt.object;
    Procman::ProcessLocation location = frame.scopeIP(*jt.context);
    Procman::PrintableFrame pframe(*jt.context, frame);
    return JObject(os)
        .field("ip", frame.rawIP())
        .field("offset", pframe.functionOffset)
        .field("trampoline", frame.isSignalTrampoline)
        .field("die", pframe.dieName)
        .field("loadaddr", location.elfReloc())
        .field("symbol", location.symbol())
        .field("source", NotAsObject{location.source()});
}

}
