#include "libpstack/dwarf.h"
#include "libpstack/elf.h"
#include "libpstack/proc.h"
#include "libpstack/dwarf_reader.h"
#include <stack>
#include <unistd.h>

extern std::ostream & operator << (std::ostream &os, const pstack::Dwarf::DIE &);

namespace pstack::Procman {
void
StackFrame::setCoreRegs(const Elf::CoreRegisters &sys)
{
#define REGMAP(number, field) Elf::setReg(regs, number, sys.field);
#include "libpstack/archreg.h"
#undef REGMAP
}

void
StackFrame::getCoreRegs(Elf::CoreRegisters &core) const
{
#define REGMAP(number, field) core.field = Elf::getReg(regs, number);
#include "libpstack/archreg.h"
#undef REGMAP
}

Elf::Addr
StackFrame::rawIP() const
{
    return Elf::getReg(regs, IPREG);
}

ProcessLocation
StackFrame::scopeIP(Process &proc) const
{
    // For a return address on the stack, it normally represents the next
    // instruction after a call. For functions that don't return, this might
    // land outside the caller function - so we subtract one, putting us in the
    // middle of the call instruction. This will also improve source line
    // details, as the actual return address is likely on the line of code
    // *after* the call rather than at it.
    //
    // There are two exceptions: first, the instruction pointer we grab from
    // the process's register state - this is the currently executing
    // instruction, so accurately reflects the position in the top stack frame.
    //
    // The other is for signal trampolines - In this case, the return address
    // has been synthesized to be the entrypoint of a function (eg,
    // __restore_rt) to handle return from the signal handler, and will be the
    // first instruction in the function - there's no previous call instruction
    // to point at, so we use it directly.
    auto raw = rawIP();
    if (raw == 0)
       return { proc, raw };
    if (mechanism == UnwindMechanism::MACHINEREGS)
       return { proc, raw };
    if (isSignalTrampoline)
       return { proc, raw };
    ProcessLocation location(proc, raw);

    const auto *lcie = location.cie();
    if (lcie != nullptr && lcie->isSignalHandler)
       return location;
    return {proc, raw - 1};
}

uintptr_t
StackFrame::getFrameBase(Process &p) const
{
    ProcessLocation location = scopeIP(p);
    const Dwarf::DIE &f = location.die();
    if (f) {
        auto base = f.attribute(Dwarf::DW_AT_frame_base);
        if (base.valid()) {
            ExpressionStack stack;
            return stack.eval(p, base, this, location.elfReloc());
        }
    }
    return 0;
}

enum DW_LLE : uint8_t {
#define DW_LLE_VAL(name, value) name = value,
#include "libpstack/dwarf/lle.h"
   DW_LLE_invalid
#undef DW_LLE_VAL
};

std::ostream &
operator <<( std::ostream &os, DW_LLE lle) {
#define DW_LLE_VAL(name, value) case name: return os << #name;
   switch (lle) {
#include "libpstack/dwarf/lle.h"
      default: return os << "(unknown LLE " << uint8_t(lle) << ")";
   }
#undef DW_LLE_VAL
};


/*
 * Evaluate an expression specified by an exprloc, or as inferred by a location list
 */
uintmax_t
ExpressionStack::eval(Process &proc, const Dwarf::DIE::Attribute &attr,
                      const StackFrame *frame, Elf::Addr reloc)
{
    Dwarf::Unit::sptr unit = attr.die.getUnit();
    const Dwarf::Info *dwarf = unit->dwarf;
    auto loc = frame->scopeIP(proc);
    auto ip = loc.address();

    const auto &unitEntry = unit->root();
    auto unitLow = unitEntry.attribute(Dwarf::DW_AT_low_pc);

    // default base address is relocation of the object + base of unit.
    uint64_t base = reloc + uintmax_t(unitLow);

    switch (attr.form()) {
        case Dwarf::DW_FORM_sec_offset:
            if (unit->version >= 5) {
                // For dwarf 5, this will be a debug_loclists entry.
                const Elf::Section &sec = dwarf->elf->getDebugSection(".debug_loclists", SHT_NULL);
                const Elf::Section &addrsec = dwarf->elf->getDebugSection(".debug_addr", SHT_NULL);
                Dwarf::DWARFReader r(sec.io(), uintmax_t(attr));
                for (;;) {
                    auto lle = DW_LLE(r.getu8());
                    switch (lle) {
                        case DW_LLE_end_of_list:
                            return 0; // failed to find a loclist for the given IP.

                        case DW_LLE_offset_pair:
                        {
                            auto start = r.getuleb128();
                            auto end = r.getuleb128();
                            auto len = r.getuleb128();
                            if (base + start <= ip && ip < base + end) {
                                Dwarf::DWARFReader exr(r.io, r.getOffset(), r.getOffset() + len);
                               return eval(proc, exr, frame, loc.elfReloc());
                            }
                            r.skip(len);
                            break;
                        }

                        case DW_LLE_base_address:
                            base = reloc + r.getuint(unit->addrlen);
                            break;

                        case DW_LLE_base_addressx:
                            {
                            auto idx = r.getuleb128();
                            addrsec.io()->readObj(idx * unit->addrlen, &base);
                            }
                            break;

                        case DW_LLE_start_length: {
                            auto start = r.getuint(unit->addrlen);
                            auto end = start + r.getuleb128();
                            auto len = r.getuleb128();
                            if (base + start <= ip && ip < base + end) {
                                Dwarf::DWARFReader exr(r.io, r.getOffset(), r.getOffset() + len);
                               return eval(proc, exr, frame, loc.elfReloc());
                            }
                            r.skip(len);
                            break;
                        }

                        default:
                            abort(); // can implement it when we see it.
                    }
                }
            } else {
                // For dwarf 4, this will be a debug_loc entry.
                auto &sec = dwarf->elf->getDebugSection(".debug_loc", SHT_NULL);

                // convert this object-relative addr to a unit-relative one
                Dwarf::DWARFReader r(sec.io(), uintmax_t(attr));
                for (;;) {
                    Elf::Addr start = r.getint(sizeof start);
                    Elf::Addr end = r.getint(sizeof end);
                    if (start == 0 && end == 0)
                        return 0;
                    auto len = r.getuint(2);
                    if (ip >= base + start && ip < base + end) {
                        Dwarf::DWARFReader exr(r.io, r.getOffset(), r.getOffset() + Elf::Word(len));
                        return eval(proc, exr, frame, loc.elfReloc());
                    }
                    r.skip(len);
                }
            }
            abort();

        case Dwarf::DW_FORM_block1:
        case Dwarf::DW_FORM_block:
        case Dwarf::DW_FORM_exprloc: {
            const auto &block = Dwarf::Block(attr);
            Dwarf::DWARFReader r(dwarf->debugInfo.io(), block.offset, block.offset + block.length);
            return eval(proc, r, frame, reloc);
        }
        default:
            abort();
    }
}

uintmax_t
ExpressionStack::eval(Process &proc, Dwarf::DWARFReader &r, const StackFrame *frame, Elf::Addr reloc)
{
    using namespace Dwarf;
    int piece = 0;
    isValue = false;
    while (!r.empty()) {
        auto op = ExpressionOp(r.getu8());
        switch (op) {
            case DW_OP_deref: {
                uintmax_t addr = poptop();
                auto value = proc.io->readObj<Elf::Addr>(addr);
                push(intptr_t(value));
                break;
            }

            case DW_OP_consts: {
                push(r.getsleb128());
                break;
            }

            case DW_OP_constu: {
                push(r.getuleb128());
                break;
            }

            case DW_OP_const2s: {
                push(int16_t(r.getu16()));
                break;
            }

            case DW_OP_const4u: {
                push(r.getu32());
                break;
            }

            case DW_OP_const4s: {
                push(int32_t(r.getu32()));
                break;
            }

            case DW_OP_minus: {
                auto tos = poptop();
                auto second = poptop();
                push(second - tos);
                break;
            }

            case DW_OP_plus: {
                auto tos = poptop();
                auto second = poptop();
                push(second + tos);
                break;
            }

            case DW_OP_breg0: case DW_OP_breg1: case DW_OP_breg2: case DW_OP_breg3:
            case DW_OP_breg4: case DW_OP_breg5: case DW_OP_breg6: case DW_OP_breg7:
            case DW_OP_breg8: case DW_OP_breg9: case DW_OP_breg10: case DW_OP_breg11:
            case DW_OP_breg12: case DW_OP_breg13: case DW_OP_breg14: case DW_OP_breg15:
            case DW_OP_breg16: case DW_OP_breg17: case DW_OP_breg18: case DW_OP_breg19:
            case DW_OP_breg20: case DW_OP_breg21: case DW_OP_breg22: case DW_OP_breg23:
            case DW_OP_breg24: case DW_OP_breg25: case DW_OP_breg26: case DW_OP_breg27:
            case DW_OP_breg28: case DW_OP_breg29: case DW_OP_breg30: case DW_OP_breg31: {
                auto offset = r.getsleb128();
                push(Elf::getReg(frame->regs, op - DW_OP_breg0) + offset);
                break;
            }

            case DW_OP_lit0: case DW_OP_lit1: case DW_OP_lit2: case DW_OP_lit3: case DW_OP_lit4:
            case DW_OP_lit5: case DW_OP_lit6: case DW_OP_lit7: case DW_OP_lit8: case DW_OP_lit9:
            case DW_OP_lit10: case DW_OP_lit11: case DW_OP_lit12: case DW_OP_lit13: case DW_OP_lit14:
            case DW_OP_lit15: case DW_OP_lit16: case DW_OP_lit17: case DW_OP_lit18: case DW_OP_lit19:
            case DW_OP_lit20: case DW_OP_lit21: case DW_OP_lit22: case DW_OP_lit23: case DW_OP_lit24:
            case DW_OP_lit25: case DW_OP_lit26: case DW_OP_lit27: case DW_OP_lit28: case DW_OP_lit29:
            case DW_OP_lit30: case DW_OP_lit31:
                push(op - DW_OP_lit0);
                break;

            case DW_OP_and: {
                auto lhs = poptop();
                auto rhs = poptop();
                push(lhs & rhs);
                break;
            }

            case DW_OP_or: {
                auto lhs = poptop();
                auto rhs = poptop();
                push(lhs | rhs);
                break;
            }

            case DW_OP_le: {
                auto rhs = poptop();
                auto lhs = poptop();
                push(value_type(lhs <= rhs));
                break;
            }

            case DW_OP_ge: {
                auto rhs = poptop();
                auto lhs = poptop();
                push(value_type(lhs >= rhs));
                break;
            }

            case DW_OP_eq: {
                auto rhs = poptop();
                auto lhs = poptop();
                push(value_type(lhs == rhs));
                break;
            }

            case DW_OP_lt: {
                auto rhs = poptop();
                auto lhs = poptop();
                push(value_type(lhs < rhs));
                break;
            }

            case DW_OP_gt: {
                auto rhs = poptop();
                auto lhs = poptop();
                push(value_type(lhs > rhs));
                break;
            }

            case DW_OP_ne: {
                auto rhs = poptop();
                auto lhs = poptop();
                push(value_type(lhs != rhs));
                break;
            }

            case DW_OP_shl: {
                auto rhs = poptop();
                auto lhs = poptop();
                push(lhs << rhs);
                break;
            }

            case DW_OP_shr: {
                auto rhs = poptop();
                auto lhs = poptop();
                push(lhs >> rhs);
                break;
            }
            case DW_OP_addr: {
                auto value = r.getuint(r.addrLen);
                push(value + reloc);
                break;
            }
            case DW_OP_call_frame_cfa:
               push(frame->cfa);
               break;
            case DW_OP_fbreg:
               // Yuk - find DW_AT_frame_base, and offset from that.
               push(frame->getFrameBase(proc) + r.getsleb128());
               break;

            case DW_OP_reg0: case DW_OP_reg1: case DW_OP_reg2: case DW_OP_reg3:
            case DW_OP_reg4: case DW_OP_reg5: case DW_OP_reg6: case DW_OP_reg7:
            case DW_OP_reg8: case DW_OP_reg9: case DW_OP_reg10: case DW_OP_reg11:
            case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14: case DW_OP_reg15:
            case DW_OP_reg16: case DW_OP_reg17: case DW_OP_reg18: case DW_OP_reg19:
            case DW_OP_reg20: case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
            case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26: case DW_OP_reg27:
            case DW_OP_reg28: case DW_OP_reg29: case DW_OP_reg30: case DW_OP_reg31:
                isValue = true;
                inReg = op - DW_OP_reg0;
                push(Elf::getReg(frame->regs, op - DW_OP_reg0));
                break;
            case DW_OP_regx:
                push(Elf::getReg(frame->regs, int(r.getsleb128())));
                break;

            case DW_OP_entry_value:
            case DW_OP_GNU_entry_value: {
                auto len = r.getuleb128();
                DWARFReader r2(r.io, r.getOffset(), r.getOffset() + len);
                push(eval(proc, r2, frame, reloc));
                break;
            }

            case DW_OP_piece: {
                auto bytes = r.getuleb128();
                auto value = poptop();
                uintmax_t mask = bytes < sizeof mask ? std::numeric_limits<uintmax_t>::max() << 8 * bytes : 0;
                value &= ~mask;
                if (piece++ != 0) {
                   // This is not the first piece - pop the existing piece off the top of the stack, and fold this in.
                   auto existing = poptop();
                   existing <<= (8 * bytes);
                   value |= existing;
                }
                push(value);
                break;
                              }

            case DW_OP_stack_value:
                break; // XXX: the returned value is not a location, but the underlying value itself.
            case DW_OP_GNU_parameter_ref:
                {
                  if (proc.context.debug)
                     *proc.context.debug << "can't handle DW_OP_GNU_parameter_ref: ";
                  auto loc = frame->scopeIP(proc);
                  auto unit = loc.die().getUnit();
                  auto off = r.getuint(4);
                  auto die = unit->offsetToDIE(DIE(), off + unit->offset);
                  if (proc.context.debug)
                     *proc.context.debug << json(die) << "\n";
                  auto attr = die.attribute(DW_AT_type);
                  if (attr) {
                     auto typeDie = DIE(attr);
                     if (proc.context.debug)
                        *proc.context.debug << json(typeDie) << "\n";
                  }
                  if (proc.context.debug)
                     *proc.context.debug << "\n";
                  return -1;
                }
                // FALLTHROUGH

            default:
                abort();
                if (proc.context.debug)
                   *proc.context.debug << "error evaluating DWARF OP " << op << " (" << int(op) << ")\n";
                return -1;
        }
    }
    return poptop();
}


StackFrame::StackFrame(UnwindMechanism mechanism, const Elf::CoreRegisters &regs_)
    : regs(regs_)
    , cfa(0)
    , mechanism(mechanism)
    , isSignalTrampoline(false)
{}

std::optional<Elf::CoreRegisters> StackFrame::unwind(Process &p) {
    ProcessLocation location = scopeIP(p);

    const Dwarf::CFI *cfi = location.cfi();
    const Dwarf::FDE *fde = location.fde();
    const Dwarf::CIE *cie = location.cie();

    if (fde == nullptr || cie == nullptr || cfi == nullptr)
        throw (Exception() << "no FDE/CIE/CFI for instruction address " << std::hex << location.address());

    if (cie->isSignalHandler)
       isSignalTrampoline = true;

    // relocate from process address to object address
    Elf::Off objaddr = location.address() - location.elfReloc();

    using namespace Dwarf;


    DWARFReader r(cfi->io, fde->instructions, fde->end);

    auto iter = location.dwarf()->callFrameForAddr.find(objaddr);
    if (iter == location.dwarf()->callFrameForAddr.end())
        location.dwarf()->callFrameForAddr[objaddr] = cie->execInsns(r, fde->iloc, objaddr);

    const CallFrame &dcf = location.dwarf()->callFrameForAddr[objaddr];

    // Given the registers available, and the state of the call unwind data,
    // calculate the CFA at this point.
    Elf::CoreRegisters out;
    switch (dcf.cfaValue.type) {
        case SAME:
        case UNDEF:
        case ARCH:
            cfa = Elf::getReg(regs, dcf.cfaReg);
            break;
        case VAL_OFFSET:
        case VAL_EXPRESSION:
        case REG:
            abort();
            break;

        case OFFSET:
            cfa = Elf::getReg(regs, dcf.cfaReg) + dcf.cfaValue.u.offset;
            break;

        case EXPRESSION: {
            ExpressionStack stack;
            auto start = dcf.cfaValue.u.expression.offset;
            auto end = start + dcf.cfaValue.u.expression.length;
            DWARFReader r(location.cfi()->io, start, end);
            cfa = stack.eval(p, r, this, location.elfReloc());
            break;
        }
        default:
            cfa = -1;
    }
    auto rarInfo = dcf.registers.find(cie->rar);

    for (const auto &entry : dcf.registers) {
        const RegisterUnwind &unwind = entry.second;
        int regno = entry.first;
        switch (unwind.type) {
            case ARCH:
#ifdef CFA_RESTORE_REGNO
                // "The CFA is defined to be the stack pointer in the calling frame."
                if (regno == CFA_RESTORE_REGNO)
                   Elf::setReg(out, regno, cfa);
                else
                   Elf::setReg(out, regno, Elf::getReg(regs, regno));
                break;
#endif
            case UNDEF:
            case SAME:
                Elf::setReg(out, regno, Elf::getReg(regs, regno));
                break;
            case OFFSET: // XXX: assume addrLen = sizeof Elf_Addr
                Elf::setReg(out, regno, p.io->readObj<Elf::Addr>(cfa + unwind.u.offset));
                break;
            case REG:
                Elf::setReg(out, regno, Elf::getReg(out,unwind.u.reg));
                break;
            case VAL_EXPRESSION:
            case EXPRESSION: {
                ExpressionStack stack;
                stack.push(cfa);
                DWARFReader reader(cfi->io, unwind.u.expression.offset,
                      unwind.u.expression.offset + unwind.u.expression.length);
                auto val = stack.eval(p, reader, this, location.elfReloc());
                // EXPRESSIONs give an address, VAL_EXPRESSION gives a literal.
                if (unwind.type == EXPRESSION)
                    p.io->readObj(val, &val);
                Elf::setReg(out, regno, val);
                break;
            }
            default:
                break;
        }
    }

    // If the return address isn't defined, then we can't unwind.
    if (rarInfo == dcf.registers.end() || rarInfo->second.type == UNDEF || cfa == 0) {
        if (p.context.verbose > 1) {
           *p.context.debug << "DWARF unwinding stopped at "
              << std::hex << location.address() << std::dec
              << ": " <<
              (rarInfo == dcf.registers.end() ? "no RAR register found"
               : rarInfo->second.type == UNDEF ? "RAR register undefined"
               : "null CFA for frame")
              << std::endl;
        }
        return std::nullopt;
    }

    // We know the RAR is defined, so make that the instruction pointer in the
    // new frame.
    if (cie && cie->rar != IPREG)
       Elf::setReg(out, IPREG, Elf::getReg(out, cie->rar));
    return out;
}


const Elf::MaybeNamedSymbol &
CodeLocation::symbol() const {
    if (!symbol_ && dwarf_) {
        symbol_ = dwarf_->elf->findSymbolByAddress(location_, STT_NOTYPE);
    }
    return symbol_;
}

Elf::MaybeNamedSymbol
ProcessLocation::symbol() const {
    if (codeloc)
        return codeloc->symbol();
    return std::nullopt;
}

const Dwarf::FDE *
CodeLocation::fde() const {
    if (fde_ == nullptr) {
        const Dwarf::CFI *cfip = cfi();
        if (cfip != nullptr)
            fde_ = cfi()->findFDE(location_);
    }
    return fde_;
}

const Dwarf::FDE *
ProcessLocation::fde() const {
    if (!codeloc)
        return nullptr;
    return codeloc->fde();
}

const Dwarf::DIE &
CodeLocation::die() const {
    if (!die_ && dwarf_) {
        Dwarf::Unit::sptr u = dwarf_->lookupUnit(location_);
        if (u) {
            die_ = u->root().findEntryForAddr(location_, Dwarf::DW_TAG_subprogram);
        }
    }
    return die_;
}

const Dwarf::DIE &
ProcessLocation::die() const {
    static Dwarf::DIE empty;
    return codeloc ? codeloc->die() : empty;
}

ProcessLocation::ProcessLocation(Process &proc, Elf::Addr address_) {
    set(proc, address_);
}

const Dwarf::CIE *
ProcessLocation::cie() const {
    const Dwarf::FDE *lfde = fde();
    if (lfde == nullptr)
        return nullptr;
    return &cfi()->getCIE(lfde->cieOff);
}

std::vector<std::pair<std::string, int>>
CodeLocation::source() const
{
    if (dwarf_)
        return dwarf_->sourceFromAddr(location_);
    return {};
}

std::vector<std::pair<std::string, int>>
ProcessLocation::source() const {
    return codeloc ? codeloc->source() : std::vector<std::pair<std::string, int>>();
}

CodeLocation::CodeLocation() : location_(0), phdr_(nullptr), cie_(nullptr), fde_(nullptr), cfi_(nullptr) {
}

CodeLocation::CodeLocation(Dwarf::Info::sptr info, const Elf::Phdr *phdr, Elf::Addr off)
    : location_(off)
    , dwarf_(std::move(info)), phdr_(phdr), cie_(nullptr), fde_(nullptr), cfi_(nullptr)
{
}

void
ProcessLocation::set(Process &proc, Elf::Addr address)
{
    auto [ elfReloc, elf, phdr ] = proc.findSegment(address);
    auto dwarf = elf ? proc.getDwarf(elf) : nullptr;
    if (dwarf) {
        codeloc = std::make_shared<CodeLocation>(dwarf, phdr, address - elfReloc);
    } else {
        this->codeloc = nullptr;
    }
    this->location = address;
}

Dwarf::CFI *
CodeLocation::cfi() const {
    Dwarf::CFI *cfi = dwarf_->getCFI();
    if (cfi == nullptr)
        return nullptr;
    return cfi;
}

const Dwarf::CFI *
ProcessLocation::cfi() const {
    if (codeloc == nullptr)
        return nullptr;
    return codeloc->cfi();
}

}
