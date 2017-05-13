#include <stack>
#include <limits>

#include <libpstack/proc.h>
#include <libpstack/elf.h>
#include <libpstack/dwarf.h>
#include <libpstack/dwarfproc.h>
#include <libpstack/dump.h>

#include <assert.h>

static int
dwarfIsArchReg(int regno)
{
#define REGMAP(regno, regname) case regno: return 1;
switch (regno) {
#include <libpstack/dwarf/archreg.h>
default: return 0;
}
#undef REGMAP

}


void
getFBreg(const Process &p, const StackFrame *frame, intmax_t offset, DwarfExpressionStack *stack)
{

   const DwarfAttribute *attr;
   if (!frame->function || (attr = frame->function->attrForName(DW_AT_frame_base)) == 0) {
      stack->push(0);
      return;
   }
   stack->push(dwarfEvalExpr(p, attr, frame, stack) + offset);
}

Elf_Addr
dwarfEvalExpr(const Process &proc, const DwarfAttribute *attr, const StackFrame *frame, DwarfExpressionStack *stack)
{
    DwarfInfo *dwarf = attr->entry->unit->dwarf;
    switch (attr->spec->form) {
        case DW_FORM_sec_offset: {
            auto sec = dwarf->elf->getSection(".debug_loc", SHT_PROGBITS);
            auto loaded = proc.findObject(frame->ip);
            auto objIp = frame->ip - loaded.reloc;
            // convert this object-relative addr to a unit-relative one
            const DwarfEntry *unitEntry = attr->entry->unit->entries.begin()->second;
            auto unitLow = unitEntry->attrForName(DW_AT_low_pc);
            auto unitHigh = unitEntry->attrForName(DW_AT_high_pc);
            Elf_Addr endAddr;
            switch (unitHigh->spec->form) {
                case DW_FORM_addr:
                    endAddr = unitHigh->value.addr;
                    break;
                case DW_FORM_data1: case DW_FORM_data2: case DW_FORM_data4: case DW_FORM_data8:
                    endAddr = unitHigh->value.sdata + unitLow->value.addr;
                    break;
                default:
                    abort();
            }
            assert(objIp >= unitLow->value.udata && objIp < endAddr);
            Elf_Addr unitIp = objIp - unitLow->value.udata;

            DWARFReader r(sec, dwarf->getVersion(), attr->value.udata, std::numeric_limits<size_t>::max());
            for (;;) {
                Elf_Addr start = r.getint(sizeof start);
                Elf_Addr end = r.getint(sizeof end);
                if (start == 0 && end == 0)
                    return 0;
                auto len = r.getuint(2);
                if (unitIp >= start && unitIp < end) {
                    DWARFReader exr(r, r.getOffset(), Elf_Word(len));
                    return dwarfEvalExpr(dwarf, proc, exr, frame, stack);
                }
                r.skip(len);
            }
        }
        case DW_FORM_exprloc: {
            auto &block = attr->value.block;
            DWARFReader r(dwarf->elf->io, dwarf->getVersion(), block.offset, block.length, 0);
            return dwarfEvalExpr(dwarf, proc, r, frame, stack);
        }
        default:
            abort();
    }
}

Elf_Addr
dwarfEvalExpr(DwarfInfo *dwarf, const Process &proc, DWARFReader &r, const StackFrame *frame, DwarfExpressionStack *stack)
{
    while (!r.empty()) {
        auto op = DwarfExpressionOp(r.getu8());
        switch (op) {
            case DW_OP_deref: {
                intmax_t addr = stack->top(); stack->pop();
                Elf_Addr value;
                proc.io->readObj(addr, &value);
                stack->push((intmax_t)(intptr_t)value);
                break;
            }

            case DW_OP_const2s: {
                stack->push(int16_t(r.getu16()));
                break;
            }

            case DW_OP_const4u: {
                stack->push(r.getu32());
                break;
            }

            case DW_OP_const4s: {
                stack->push(int32_t(r.getu32()));
                break;
            }

            case DW_OP_minus: {
                Elf_Addr top = stack->top();
                stack->pop();
                Elf_Addr second = stack->top();
                stack->pop();
                top = -top;
                stack->push(second + top);
                break;
            }

            case DW_OP_plus: {
                Elf_Addr top = stack->top();
                stack->pop();
                Elf_Addr second = stack->top();
                stack->pop();
                stack->push(second + top);
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
                stack->push(frame->regs.reg[op - DW_OP_breg0] + offset);
                break;
            }

            case DW_OP_lit0: case DW_OP_lit1: case DW_OP_lit2: case DW_OP_lit3: case DW_OP_lit4:
            case DW_OP_lit5: case DW_OP_lit6: case DW_OP_lit7: case DW_OP_lit8: case DW_OP_lit9:
            case DW_OP_lit10: case DW_OP_lit11: case DW_OP_lit12: case DW_OP_lit13: case DW_OP_lit14:
            case DW_OP_lit15: case DW_OP_lit16: case DW_OP_lit17: case DW_OP_lit18: case DW_OP_lit19:
            case DW_OP_lit20: case DW_OP_lit21: case DW_OP_lit22: case DW_OP_lit23: case DW_OP_lit24:
            case DW_OP_lit25: case DW_OP_lit26: case DW_OP_lit27: case DW_OP_lit28: case DW_OP_lit29:
            case DW_OP_lit30: case DW_OP_lit31:
                stack->push(op - DW_OP_lit0);
                break;

            case DW_OP_and: {
                Elf_Addr lhs = stack->top();
                stack->pop();
                Elf_Addr rhs = stack->top();
                stack->pop();
                stack->push(lhs & rhs);
                break;
            }

            case DW_OP_or: {
                Elf_Addr lhs = stack->top();
                stack->pop();
                Elf_Addr rhs = stack->top();
                stack->pop();
                stack->push(lhs | rhs);
                break;
            }

            case DW_OP_le: {
                Elf_Addr rhs = stack->top();
                stack->pop();
                Elf_Addr lhs = stack->top();
                stack->pop();
                stack->push(lhs <= rhs);
                break;
            }

            case DW_OP_ge: {
                Elf_Addr rhs = stack->top();
                stack->pop();
                Elf_Addr lhs = stack->top();
                stack->pop();
                stack->push(lhs >= rhs);
                break;
            }

            case DW_OP_eq: {
                Elf_Addr rhs = stack->top();
                stack->pop();
                Elf_Addr lhs = stack->top();
                stack->pop();
                stack->push(lhs == rhs);
                break;
            }

            case DW_OP_lt: {
                Elf_Addr rhs = stack->top();
                stack->pop();
                Elf_Addr lhs = stack->top();
                stack->pop();
                stack->push(lhs < rhs);
                break;
            }

            case DW_OP_gt: {
                Elf_Addr rhs = stack->top();
                stack->pop();
                Elf_Addr lhs = stack->top();
                stack->pop();
                stack->push(lhs > rhs);
                break;
            }

            case DW_OP_ne: {
                Elf_Addr rhs = stack->top();
                stack->pop();
                Elf_Addr lhs = stack->top();
                stack->pop();
                stack->push(lhs != rhs);
                break;
            }

            case DW_OP_shl: {
                Elf_Addr rhs = stack->top();
                stack->pop();
                Elf_Addr lhs = stack->top();
                stack->pop();
                stack->push(lhs << rhs);
                break;
            }

            case DW_OP_shr: {
                Elf_Addr rhs = stack->top();
                stack->pop();
                Elf_Addr lhs = stack->top();
                stack->pop();
                stack->push(lhs >> rhs);
                break;
            }

            case DW_OP_addr: {
                auto value = r.getuint(r.addrLen);
                for (auto &o : proc.objects) {
                   if (o.object == dwarf->elf) {
                      value += o.reloc;
                   }
                }
                stack->push(value);
                break;
            }
            case DW_OP_call_frame_cfa:
               stack->push(frame->cfa);
               break;
            case DW_OP_fbreg:
               // Yuk - find DW_AT_frame_base, and offset from that.
               getFBreg(proc, frame, r.getsleb128(), stack);
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
                stack->push(frame->regs.reg[op - DW_OP_reg0]);
                break;
            case DW_OP_regx:
                stack->push(frame->regs.reg[r.getsleb128()]);
                break;

            case DW_OP_entry_value: case DW_OP_GNU_entry_value: {
                auto len = r.getuleb128();
                DWARFReader r2(r, r.getOffset(), len);
                stack->push(dwarfEvalExpr(dwarf, proc, r2, frame, stack));
                break;
            }

            case DW_OP_stack_value:
                break; // XXX: the returned value is not a location, but the underlying value itself.

            default:
                std::clog << "error evaluating DWARF OP " << op << " (" << int(op) << ")\n";
                return -1;
        }
    }
    intmax_t rv = stack->top();
    stack->pop();
    return rv;
}


Elf_Addr
dwarfGetCFA(DwarfInfo *dwarf, const Process &proc,
      const DwarfCallFrame *cfi, const StackFrame *frame)
{
    switch (cfi->cfaValue.type) {
        case SAME:
        case VAL_OFFSET:
        case VAL_EXPRESSION:
        case REG:
        case UNDEF:
        case ARCH:
            abort();
            break;

        case OFFSET:
            return dwarfGetReg(&frame->regs, cfi->cfaReg) + cfi->cfaValue.u.offset;
        case EXPRESSION: {
            DwarfExpressionStack stack;
            DWARFReader r(dwarf->elf->io, dwarf->getVersion(),
                    cfi->cfaValue.u.expression.offset,
                    cfi->cfaValue.u.expression.length,
                    0);
            return dwarfEvalExpr(dwarf, proc, r, frame, &stack);
        }
    }
    return -1;
}



bool
dwarfUnwind(Process &p, const StackFrame *in, StackFrame *out, Elf_Addr *cfa)
{
    auto elf = p.findObject(in->ip);
    DwarfInfo *dwarf;
    Elf_Off objaddr = in->ip - elf.reloc; // relocate process address to object address

    const DwarfFDE *fde;
    DwarfFrameInfo *dwarfFrame;

    // Try and find DWARF data with debug frame information, or an eh_frame section.
    for (bool debug : {true, false}) {
       dwarf = p.getDwarf(elf.object, debug);
       if (dwarf) {
          dwarfFrame = dwarf->debugFrame ? dwarf->debugFrame.get() : dwarf->ehFrame.get();
          if (dwarfFrame)
             break;
       }
    }
    if (!dwarfFrame)
       return false;
    fde = dwarfFrame->findFDE(objaddr);
    if (!fde)
       return false;

    DWARFReader r(elf.object->io, dwarf->getVersion(), fde->instructions, fde->end - fde->instructions, 0);

    auto iter = dwarf->callFrameForAddr.find(objaddr);
    if (iter == dwarf->callFrameForAddr.end()) {
        const DwarfCallFrame frame = fde->cie->execInsns(r, dwarf->getVersion(), fde->iloc, objaddr);
        dwarf->callFrameForAddr[objaddr] = frame;
    }

    const DwarfCallFrame &frame = dwarf->callFrameForAddr[objaddr];

    // Given the registers available, and the state of the call unwind data, calculate the CFA at this point.
    *cfa = dwarfGetCFA(dwarf, p, &frame, in);
#ifdef CFA_RESTORE_REGNO
    // "The CFA is defined to be the stack pointer in the calling frame."
    dwarfSetReg(&out->regs, CFA_RESTORE_REGNO, *cfa);
#endif

    for (auto &entry : frame.registers) {
        const auto &unwind = entry.second;
        const int regno = entry.first;
        switch (unwind.type) {
            case UNDEF:
            case SAME:
                dwarfSetReg(&out->regs, regno, dwarfGetReg(&in->regs, regno));
                break;
            case OFFSET: {
                Elf_Addr reg; // XXX: assume addrLen = sizeof Elf_Addr
                p.io->readObj(*cfa + unwind.u.offset, &reg);
                dwarfSetReg(&out->regs, regno, reg);
                break;
            }
            case REG:
                dwarfSetReg(&out->regs, regno, dwarfGetReg(&in->regs, unwind.u.reg));
                break;

            case VAL_EXPRESSION:
            case EXPRESSION: {
                DwarfExpressionStack stack;
                stack.push(*cfa);
                DWARFReader reader(elf.object->io, dwarf->getVersion(), unwind.u.expression.offset, unwind.u.expression.length, 0);
                auto val = dwarfEvalExpr(dwarf, p, reader, in, &stack);
                // EXPRESSIONs give an address, VAL_EXPRESSION gives a literal.
                if (unwind.type == EXPRESSION)
                    p.io->readObj(val, &val);
                dwarfSetReg(&out->regs, regno, val);
                break;
            }

            default:
            case ARCH:
                abort();
                break;
        }
    }

    // If the return address isn't defined, then we can't unwind.
    auto rar = fde->cie->rar;
    auto rarInfo = frame.registers.find(rar);
    if (rarInfo == frame.registers.end() || rarInfo->second.type == UNDEF)
        return false;

    out->ip = dwarfGetReg(&out->regs, rar);

    return true;
}

void
dwarfSetReg(DwarfRegisters *regs, int regno, uintmax_t regval)
{
    regs->reg[regno] = regval;
}

uintmax_t
dwarfGetReg(const DwarfRegisters *regs, int regno)
{
    return regs->reg[regno];
}

DwarfRegisters *
dwarfPtToDwarf(DwarfRegisters *dwarf, const CoreRegisters *sys)
{
#define REGMAP(number, field) dwarf->reg[number] = sys->field;
#include <libpstack/dwarf/archreg.h>
#undef REGMAP
    return dwarf;
}

const DwarfRegisters *
dwarfDwarfToPt(CoreRegisters *core, const DwarfRegisters *dwarf)
{
#define REGMAP(number, field) core->field = dwarf->reg[number];
#include <libpstack/dwarf/archreg.h>
#undef REGMAP
    return dwarf;
}

