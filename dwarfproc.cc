#include <stack>
#include <limits>

#include <libpstack/proc.h>
#include <libpstack/elf.h>
#include <libpstack/dwarf.h>
#include <libpstack/dump.h>

#include <assert.h>

void
StackFrame::setCoreRegs(const CoreRegisters &sys)
{
#define REGMAP(number, field) setReg(number, sys.field);
#include <libpstack/dwarf/archreg.h>
#undef REGMAP
}

void
StackFrame::getCoreRegs(CoreRegisters &core) const
{
#define REGMAP(number, field) core.field = getReg(number);
#include <libpstack/dwarf/archreg.h>
#undef REGMAP
}

void
StackFrame::getFrameBase(const Process &p, intmax_t offset, DwarfExpressionStack *stack) const
{
   const DwarfAttribute *attr;
   if (!function || (attr = function->attrForName(DW_AT_frame_base)) == 0) {
      stack->push(0);
      return;
   }
   stack->push(stack->eval(p, attr, this) + offset);
}

Elf_Addr
DwarfExpressionStack::eval(const Process &proc, const DwarfAttribute *attr, const StackFrame *frame)
{
    DwarfInfo *dwarf = attr->entry->unit->dwarf;
    switch (attr->spec->form) {
        case DW_FORM_sec_offset: {
            auto sec = dwarf->elf->getSection(".debug_loc", SHT_PROGBITS);
            Elf_Off reloc;
            // XXX: this might be the debug dwarf, and not have the object code
            auto obj = proc.findObject(frame->ip, &reloc);
            if (!obj) {
               throw Exception() << "no object for evaluating DWARF expression";
            }
            auto objIp = frame->ip - reloc;
            // convert this object-relative addr to a unit-relative one
            const DwarfEntry *unitEntry = attr->entry->unit->entries.begin()->second;
            auto unitLow = unitEntry->attrForName(DW_AT_low_pc);
#ifndef NDEBUG
            auto unitHigh = unitEntry->attrForName(DW_AT_high_pc);
            Elf_Addr endAddr;
            if (unitHigh) {
               switch (unitHigh->spec->form) {
                   case DW_FORM_addr:
                       endAddr = unitHigh->value.addr;
                       break;
                   case DW_FORM_data1: case DW_FORM_data2: case DW_FORM_data4: case DW_FORM_data8: case DW_FORM_udata:
                       endAddr = unitHigh->value.sdata + unitLow->value.addr;
                       break;
                   default:
                       abort();
               }
               assert(objIp >= unitLow->value.udata && objIp < endAddr);
            }
#endif
            Elf_Addr unitIp = objIp - unitLow->value.udata;

            DWARFReader r(sec, attr->value.udata, std::numeric_limits<size_t>::max());
            for (;;) {
                Elf_Addr start = r.getint(sizeof start);
                Elf_Addr end = r.getint(sizeof end);
                if (start == 0 && end == 0)
                    return 0;
                auto len = r.getuint(2);
                if (unitIp >= start && unitIp < end) {
                    DWARFReader exr(r, r.getOffset(), Elf_Word(len));
                    return eval(proc, exr, frame);
                }
                r.skip(len);
            }
        }
        case DW_FORM_exprloc: {
            auto &block = attr->value.block;
            DWARFReader r(dwarf->elf->io, block.offset, block.length, 0);
            return eval(proc, r, frame);
        }
        default:
            abort();
    }
}

Elf_Addr
DwarfExpressionStack::eval(const Process &proc, DWARFReader &r, const StackFrame *frame)
{
    isReg = false;
    while (!r.empty()) {
        auto op = DwarfExpressionOp(r.getu8());
        switch (op) {
            case DW_OP_deref: {
                intmax_t addr = poptop();
                Elf_Addr value;
                proc.io->readObj(addr, &value);
                push((intmax_t)(intptr_t)value);
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
                Elf_Addr tos = poptop();
                Elf_Addr second = poptop();
                push(second - tos);
                break;
            }

            case DW_OP_plus: {
                Elf_Addr tos = poptop();
                Elf_Addr second = poptop();
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
                Elf_Off offset = r.getsleb128();
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
                Elf_Addr lhs = poptop();
                Elf_Addr rhs = poptop();
                push(lhs & rhs);
                break;
            }

            case DW_OP_or: {
                Elf_Addr lhs = poptop();
                Elf_Addr rhs = poptop();
                push(lhs | rhs);
                break;
            }

            case DW_OP_le: {
                Elf_Addr rhs = poptop();
                Elf_Addr lhs = poptop();
                push(lhs <= rhs);
                break;
            }

            case DW_OP_ge: {
                Elf_Addr rhs = poptop();
                Elf_Addr lhs = poptop();
                push(lhs >= rhs);
                break;
            }

            case DW_OP_eq: {
                Elf_Addr rhs = poptop();
                Elf_Addr lhs = poptop();
                push(lhs == rhs);
                break;
            }

            case DW_OP_lt: {
                Elf_Addr rhs = poptop();
                Elf_Addr lhs = poptop();
                push(lhs < rhs);
                break;
            }

            case DW_OP_gt: {
                Elf_Addr rhs = poptop();
                Elf_Addr lhs = poptop();
                push(lhs > rhs);
                break;
            }

            case DW_OP_ne: {
                Elf_Addr rhs = poptop();
                Elf_Addr lhs = poptop();
                push(lhs != rhs);
                break;
            }

            case DW_OP_shl: {
                Elf_Addr rhs = poptop();
                Elf_Addr lhs = poptop();
                push(lhs << rhs);
                break;
            }

            case DW_OP_shr: {
                Elf_Addr rhs = poptop();
                Elf_Addr lhs = poptop();
                push(lhs >> rhs);
                break;
            }
            case DW_OP_addr: {
                auto value = r.getuint(r.addrLen);
                push(value);
                break;
            }
            case DW_OP_call_frame_cfa:
               push(frame->cfa);
               break;
            case DW_OP_fbreg:
               // Yuk - find DW_AT_frame_base, and offset from that.
               frame->getFrameBase(proc, r.getsleb128(), this);
               break;

            // XXX: this is wrong - this indicates an object contained in a register, not a location contained in a register.
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

            case DW_OP_entry_value: case DW_OP_GNU_entry_value: {
                auto len = r.getuleb128();
                DWARFReader r2(r, r.getOffset(), len);
                push(eval(proc, r2, frame));
                break;
            }

            case DW_OP_stack_value:
                break; // XXX: the returned value is not a location, but the underlying value itself.

            default:
                std::clog << "error evaluating DWARF OP " << op << " (" << int(op) << ")\n";
                return -1;
        }
    }
    return poptop();
}

Elf_Addr
StackFrame::getCFA(const Process &proc, const DwarfCallFrame &dcf) const
{
    switch (dcf.cfaValue.type) {
        case SAME:
            return getReg(dcf.cfaReg);
        case VAL_OFFSET:
        case VAL_EXPRESSION:
        case REG:
        case UNDEF:
        case ARCH:
            abort();
            break;

        case OFFSET:
            return getReg(dcf.cfaReg) + dcf.cfaValue.u.offset;
        case EXPRESSION: {
            DwarfExpressionStack stack;
            DWARFReader r(dwarf->elf->io, dcf.cfaValue.u.expression.offset, dcf.cfaValue.u.expression.length, 0);
            return stack.eval(proc, r, this);
        }
    }
    return -1;
}

StackFrame *
StackFrame::unwind(Process &p)
{
    Elf_Off reloc;
    auto elf = p.findObject(ip, &reloc);
    if (!elf)
       return 0;
    Elf_Off objaddr = ip - reloc; // relocate process address to object address
    // Try and find DWARF data with debug frame information, or an eh_frame section.
    const DwarfFDE *fde = 0;
    for (bool debug : {true, false}) {
       dwarf = p.getDwarf(elf, debug);
       if (dwarf) {
          auto frames = { dwarf->debugFrame.get(), dwarf->ehFrame.get() };
          for (auto frame : frames) {
             if (frame) {
                 fde = frame->findFDE(objaddr);
                 if (fde)
                    break;
             }
          }
          if (fde)
              break;
       }
    }
    if (!fde)
       return 0;

    DWARFReader r(dwarf->elf->io, fde->instructions, fde->end - fde->instructions, 0);

    auto iter = dwarf->callFrameForAddr.find(objaddr);
    if (iter == dwarf->callFrameForAddr.end()) {
        const DwarfCallFrame frame = fde->cie->execInsns(r, fde->iloc, objaddr);
        dwarf->callFrameForAddr[objaddr] = frame;
    }

    const DwarfCallFrame &dcf = dwarf->callFrameForAddr[objaddr];

    // Given the registers available, and the state of the call unwind data, calculate the CFA at this point.
    cfa = getCFA(p, dcf);

    StackFrame *out = new StackFrame();
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
                Elf_Addr reg; // XXX: assume addrLen = sizeof Elf_Addr
                p.io->readObj(cfa + unwind.u.offset, &reg);
                out->setReg(regno, reg);
                break;
            }
            case REG:
                out->setReg(regno, getReg(unwind.u.reg));
                break;

            case VAL_EXPRESSION:
            case EXPRESSION: {
                DwarfExpressionStack stack;
                stack.push(cfa);
                DWARFReader reader(elf->io, unwind.u.expression.offset, unwind.u.expression.length, 0);
                auto val = stack.eval(p, reader, this);
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
    auto rar = fde->cie->rar;
    auto rarInfo = dcf.registers.find(rar);
    if (rarInfo == dcf.registers.end() || rarInfo->second.type == UNDEF) {
        delete out;
        return 0;
    }

    out->ip = out->getReg(rar);
    return out;
}

void
StackFrame::setReg(unsigned regno, uintmax_t regval)
{
    regs[regno] = regval;
}


uintmax_t
StackFrame::getReg(unsigned regno) const
{
    auto i = regs.find(regno);
    return i != regs.end() ? i->second : 0;
}
