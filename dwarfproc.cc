#include "libpstack/dwarf.h"
#include "libpstack/elf.h"
#include "libpstack/proc.h"

#include <cassert>
#include <limits>
#include <stack>
extern std::ostream & operator << (std::ostream &os, const Dwarf::DIE &dieo);

namespace Dwarf {
void
StackFrame::setCoreRegs(const Elf::CoreRegisters &sys)
{
#define REGMAP(number, field) setReg(number, sys.field);
#include "libpstack/dwarf/archreg.h"
#undef REGMAP
}

void
StackFrame::getCoreRegs(Elf::CoreRegisters &core) const
{
#define REGMAP(number, field) core.field = getReg(number);
#include "libpstack/dwarf/archreg.h"
#undef REGMAP
}

Elf::Addr
StackFrame::rawIP() const
{
    return getReg(cie ? cie->rar : IPREG);
}

Elf::Addr
StackFrame::scopeIP() const
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
    // The other is for signal trampolines - this is the first instruction that
    // executes on return from the signal handler, and the stack frame is
    // synthetically configured so this instruction is in fact the first one in
    // the trampoline function (eg, __restore_rt)
    auto raw = rawIP();
    if (raw == 0)
       return 0;
    if (mechanism == UnwindMechanism::MACHINEREGS || (cie != nullptr && cie->isSignalHandler))
       return raw;
    return raw - 1;
}


void
StackFrame::getFrameBase(const Process &p, intmax_t offset, ExpressionStack *stack) const
{
   if (function) {
       auto base = function.attribute(DW_AT_frame_base);
       if (base.valid()) {
           stack->push(stack->eval(p, base, this, elfReloc) + offset);
           stack->isReg = false;
           return;
       }
   }
   stack->push(0);
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
Elf::Addr
ExpressionStack::eval(const Process &proc, const Attribute &attr,
                      const StackFrame *frame, Elf::Addr reloc)
{
    Unit::sptr unit = attr.die().getUnit();
    const Info *dwarf = unit->dwarf;
    auto ip = frame->scopeIP();

    const auto &unitEntry = unit->root();
    Attribute unitLow = unitEntry.attribute(DW_AT_low_pc);

    // default base address is relocation of the object + base of unit.
    uint64_t base = reloc + uintmax_t(unitLow);

    switch (attr.form()) {
        case DW_FORM_sec_offset:
            if (unit->version >= 5) {
                // For dwarf 5, this will be a debug_loclists entry.
                auto &sec = dwarf->elf->getSection(".debug_loclists", SHT_PROGBITS);
                DWARFReader r(sec.io, uintmax_t(attr));
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
                               DWARFReader exr(r.io, r.getOffset(), r.getOffset() + len);
                               return eval(proc, exr, frame, frame->elfReloc);
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
                            auto &addrsec = dwarf->elf->getSection(".debug_addr", SHT_PROGBITS);
                            addrsec.io->readObj(idx * unit->addrlen, &base);
                            }
                            break;


                        default:
                            abort(); // can implement it when we see it.
                    }
                }
            } else {
                // For dwarf 4, this will be a debug_loc entry.
                auto &sec = dwarf->elf->getSection(".debug_loc", SHT_PROGBITS);
                // convert this object-relative addr to a unit-relative one

                DWARFReader r(sec.io, uintmax_t(attr));
                for (;;) {
                    Elf::Addr start = r.getint(sizeof start);
                    Elf::Addr end = r.getint(sizeof end);
                    if (start == 0 && end == 0)
                        return 0;
                    auto len = r.getuint(2);
                    if (ip >= base + start && ip < base + end) {
                        DWARFReader exr(r.io, r.getOffset(), r.getOffset() + Elf::Word(len));
                        return eval(proc, exr, frame, frame->elfReloc);
                    }
                    r.skip(len);
                }
            }
            abort();

        case DW_FORM_block1:
        case DW_FORM_block:
        case DW_FORM_exprloc: {
            const auto &block = Block(attr);
            DWARFReader r(dwarf->io, block.offset, block.offset + block.length);
            return eval(proc, r, frame, reloc);
        }
        default:
            abort();
    }
}

Elf::Addr
ExpressionStack::eval(const Process &proc, DWARFReader &r, const StackFrame *frame, Elf::Addr reloc)
{
    isReg = false;
    while (!r.empty()) {
        auto op = ExpressionOp(r.getu8());
        switch (op) {
            case DW_OP_deref: {
                intmax_t addr = poptop();
                Elf::Addr value;
                proc.io->readObj(addr, &value);
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
                Elf::Addr tos = poptop();
                Elf::Addr second = poptop();
                push(second - tos);
                break;
            }

            case DW_OP_plus: {
                Elf::Addr tos = poptop();
                Elf::Addr second = poptop();
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
                Elf::Off offset = r.getsleb128();
                push(frame->getReg(op - DW_OP_breg0) + offset);
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
                Elf::Addr lhs = poptop();
                Elf::Addr rhs = poptop();
                push(lhs & rhs);
                break;
            }

            case DW_OP_or: {
                Elf::Addr lhs = poptop();
                Elf::Addr rhs = poptop();
                push(lhs | rhs);
                break;
            }

            case DW_OP_le: {
                Elf::Addr rhs = poptop();
                Elf::Addr lhs = poptop();
                push(value_type(lhs <= rhs));
                break;
            }

            case DW_OP_ge: {
                Elf::Addr rhs = poptop();
                Elf::Addr lhs = poptop();
                push(value_type(lhs >= rhs));
                break;
            }

            case DW_OP_eq: {
                Elf::Addr rhs = poptop();
                Elf::Addr lhs = poptop();
                push(value_type(lhs == rhs));
                break;
            }

            case DW_OP_lt: {
                Elf::Addr rhs = poptop();
                Elf::Addr lhs = poptop();
                push(value_type(lhs < rhs));
                break;
            }

            case DW_OP_gt: {
                Elf::Addr rhs = poptop();
                Elf::Addr lhs = poptop();
                push(value_type(lhs > rhs));
                break;
            }

            case DW_OP_ne: {
                Elf::Addr rhs = poptop();
                Elf::Addr lhs = poptop();
                push(value_type(lhs != rhs));
                break;
            }

            case DW_OP_shl: {
                Elf::Addr rhs = poptop();
                Elf::Addr lhs = poptop();
                push(lhs << rhs);
                break;
            }

            case DW_OP_shr: {
                Elf::Addr rhs = poptop();
                Elf::Addr lhs = poptop();
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
               frame->getFrameBase(proc, r.getsleb128(), this);
               break;

            case DW_OP_reg0: case DW_OP_reg1: case DW_OP_reg2: case DW_OP_reg3:
            case DW_OP_reg4: case DW_OP_reg5: case DW_OP_reg6: case DW_OP_reg7:
            case DW_OP_reg8: case DW_OP_reg9: case DW_OP_reg10: case DW_OP_reg11:
            case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14: case DW_OP_reg15:
            case DW_OP_reg16: case DW_OP_reg17: case DW_OP_reg18: case DW_OP_reg19:
            case DW_OP_reg20: case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
            case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26: case DW_OP_reg27:
            case DW_OP_reg28: case DW_OP_reg29: case DW_OP_reg30: case DW_OP_reg31:
                isReg = true;
                inReg = op - DW_OP_reg0;
                push(frame->getReg(op - DW_OP_reg0));
                break;
            case DW_OP_regx:
                push(frame->getReg(r.getsleb128()));
                break;

            case DW_OP_entry_value:
            case DW_OP_GNU_entry_value: {
                auto len = r.getuleb128();
                DWARFReader r2(r.io, r.getOffset(), r.getOffset() + len);
                push(eval(proc, r2, frame, reloc));
                break;
            }

            case DW_OP_stack_value:
                break; // XXX: the returned value is not a location, but the underlying value itself.
            case DW_OP_GNU_parameter_ref:
                {
                  auto unit = frame->function.getUnit();
                  auto off = r.getuint(4);
                  auto die = unit->offsetToDIE(DIE(), off + unit->offset);
                  std::clog << die << "\n";
                  auto attr = die.attribute(DW_AT_type);
                  if (attr) {
                     auto typeDie = DIE(attr);
                     std::clog << typeDie << "\n";
                  }
                }
                // FALLTHROUGH

            default:
                std::clog << "error evaluating DWARF OP " << op << " (" << int(op) << ")\n";
                return -1;
        }
    }
    return poptop();
}

Elf::Addr
StackFrame::getCFA(const Process &proc, const CallFrame &dcf) const
{
    switch (dcf.cfaValue.type) {
        case SAME:
        case UNDEF:
            return getReg(dcf.cfaReg);
        case VAL_OFFSET:
        case VAL_EXPRESSION:
        case REG:
        case ARCH:
            abort();
            break;

        case OFFSET:
            return getReg(dcf.cfaReg) + dcf.cfaValue.u.offset;
        case EXPRESSION: {
            ExpressionStack stack;
            auto start = dcf.cfaValue.u.expression.offset;
            auto end = start + dcf.cfaValue.u.expression.length;
            DWARFReader r(frameInfo->io, start, end);
            return stack.eval(proc, r, this, elfReloc);
        }
    }
    return -1;
}

StackFrame *
StackFrame::unwind(Process &p)
{
    std::tie(elfReloc, elf, phdr) = p.findSegment(scopeIP());
    if (elf == nullptr)
        throw (Exception() << "no image for instruction address "
              << std::hex << scopeIP() << std::dec);

    // relocate from process address to object address
    Elf::Off objaddr = scopeIP() - elfReloc;

    // Try and find DWARF data with debug frame information, or an eh_frame section.
    dwarf = p.getDwarf(elf);
    if (dwarf) {
        auto frames = { dwarf->ehFrame.get(), dwarf->debugFrame.get() };
        for (auto f : frames) {
            if (f != nullptr) {
                fde = f->findFDE(objaddr);
                if (fde != nullptr) {
                    frameInfo = f;
                    cie = &f->cies[fde->cieOff];
                    break;
                }
            }
        }
    }
    if (fde == nullptr)
        throw (Exception() << "no FDE for instruction address "
              << std::hex << scopeIP() << std::dec << " in " << *elf->io);

    DWARFReader r(frameInfo->io, fde->instructions, fde->end);

    auto iter = dwarf->callFrameForAddr.find(objaddr);
    if (iter == dwarf->callFrameForAddr.end())
        dwarf->callFrameForAddr[objaddr] = cie->execInsns(r, fde->iloc, objaddr);

    const CallFrame &dcf = dwarf->callFrameForAddr[objaddr];

    // Given the registers available, and the state of the call unwind data,
    // calculate the CFA at this point.
    cfa = getCFA(p, dcf);
    auto rarInfo = dcf.registers.find(cie->rar);

    auto out = new StackFrame(UnwindMechanism::DWARF);
#ifdef CFA_RESTORE_REGNO
    // "The CFA is defined to be the stack pointer in the calling frame."
    out->setReg(CFA_RESTORE_REGNO, cfa);
#endif
    for (auto &entry : dcf.registers) {
        const auto &unwind = entry.second;
        const int regno = entry.first;
        switch (unwind.type) {
            case UNDEF:
            case SAME:
                out->setReg(regno, getReg(regno));
                break;
            case OFFSET: {
                Elf::Addr reg; // XXX: assume addrLen = sizeof Elf_Addr
                p.io->readObj(cfa + unwind.u.offset, &reg);
                out->setReg(regno, reg);
                break;
            }
            case REG:
                out->setReg(regno, getReg(unwind.u.reg));
                break;

            case VAL_EXPRESSION:
            case EXPRESSION: {
                ExpressionStack stack;
                stack.push(cfa);
                DWARFReader reader(frameInfo->io, unwind.u.expression.offset,
                      unwind.u.expression.offset + unwind.u.expression.length);
                auto val = stack.eval(p, reader, this, elfReloc);
                // EXPRESSIONs give an address, VAL_EXPRESSION gives a literal.
                if (unwind.type == EXPRESSION)
                    p.io->readObj(val, &val);
                out->setReg(regno, val);
                break;
            }

            default:
            case ARCH:
                break;
        }
    }

    // If the return address isn't defined, then we can't unwind.
    if (rarInfo == dcf.registers.end() || rarInfo->second.type == UNDEF) {
        if (verbose > 1) {
           *debug << "DWARF unwinding stopped at "
              << std::hex << scopeIP() << std::dec
              << ": " << (rarInfo == dcf.registers.end() ?
                    "no RAR register found" : "RAR register undefined")
              << std::endl;
        }
        delete out;
        return nullptr;
    }
    return out;
}

void
StackFrame::setReg(unsigned regno, cpureg_t regval)
{
    regs[regno] = regval;
}

cpureg_t
StackFrame::getReg(unsigned regno) const
{
    auto i = regs.find(regno);
    return i != regs.end() ? i->second : 0;
}
}
