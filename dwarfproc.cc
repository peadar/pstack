#include <stack>

#include <libpstack/proc.h>
#include <libpstack/elf.h>
#include <libpstack/dwarf.h>
#include <libpstack/dwarfproc.h>
#include <libpstack/dump.h>


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



Elf_Addr
dwarfEvalExpr(DwarfInfo *dwarf, const Process &proc, DWARFReader r, const DwarfRegisters *frame, DwarfExpressionStack *stack)
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
                stack->push(frame->reg[op - DW_OP_breg0] + offset);
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

            case DW_OP_reg0: case DW_OP_reg1: case DW_OP_reg2: case DW_OP_reg3:
            case DW_OP_reg4: case DW_OP_reg5: case DW_OP_reg6: case DW_OP_reg7:
            case DW_OP_reg8: case DW_OP_reg9: case DW_OP_reg10: case DW_OP_reg11:
            case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14: case DW_OP_reg15:
            case DW_OP_reg16: case DW_OP_reg17: case DW_OP_reg18: case DW_OP_reg19:
            case DW_OP_reg20: case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
            case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26: case DW_OP_reg27:
            case DW_OP_reg28: case DW_OP_reg29: case DW_OP_reg30: case DW_OP_reg31:
                stack->push(frame->reg[op - DW_OP_reg0]);
                break;
            case DW_OP_regx:
                stack->push(frame->reg[r.getsleb128()]);
                break;
            default:
                abort();
        }
    }
    intmax_t rv = stack->top();
    stack->pop();
    return rv;
}


Elf_Addr
dwarfGetCFA(DwarfInfo *dwarf, const Process &proc,
      const DwarfCallFrame *frame, const DwarfRegisters *regs)
{
    switch (frame->cfaValue.type) {
        case SAME:
        case VAL_OFFSET:
        case VAL_EXPRESSION:
        case REG:
        case UNDEF:
        case ARCH:
            abort();
            break;

        case OFFSET:
            return dwarfGetReg(regs, frame->cfaReg) + frame->cfaValue.u.offset;
        case EXPRESSION: {
            DwarfExpressionStack stack;
            DWARFReader r(dwarf->elf->io, dwarf->getVersion(),
                    frame->cfaValue.u.expression.offset,
                    frame->cfaValue.u.expression.length,
                    0);
            return dwarfEvalExpr(dwarf, proc, r, regs, &stack);
        }
    }
    return -1;
}



bool
dwarfUnwind(Process &p, DwarfRegisters *regs, Elf_Addr &procaddr)
{
    DwarfRegisters newRegs;
    auto elf = p.findObject(procaddr);
    DwarfInfo *dwarf;
    Elf_Off objaddr = procaddr - elf.reloc; // relocate process address to object address

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

    const DwarfCallFrame frame = dwarf->callFrameForAddr[objaddr];

    // Given the registers available, and the state of the call unwind data, calculate the CFA at this point.
    Elf_Addr cfa = dwarfGetCFA(dwarf, p, &frame, regs);

    for (int i = 0; i < MAXREG; i++) {
        if (!dwarfIsArchReg(i))
            continue;

        auto unwind = frame.registers + i;
        switch (unwind->type) {
            case UNDEF:
            case SAME:
                dwarfSetReg(&newRegs, i, dwarfGetReg(regs, i));
                break;
            case OFFSET: {
                Elf_Addr reg; // XXX: assume addrLen = sizeof Elf_Addr
                p.io->readObj(cfa + unwind->u.offset, &reg);
                dwarfSetReg(&newRegs, i, reg);
                break;
            }
            case REG:
                dwarfSetReg(&newRegs, i, dwarfGetReg(regs, unwind->u.reg));
                break;

            case VAL_EXPRESSION:
            case EXPRESSION: {
                DwarfExpressionStack stack;
                stack.push(cfa);
                DWARFReader reader(elf.object->io, dwarf->getVersion(), unwind->u.expression.offset, unwind->u.expression.length, 0);
                auto val = dwarfEvalExpr(dwarf, p, reader, regs, &stack);
                // EXPRESSIONs give an address, VAL_EXPRESSION gives a literal.
                if (unwind->type == EXPRESSION)
                    p.io->readObj(val, &val);
                dwarfSetReg(&newRegs, i, val);
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
    if (frame.registers[rar].type == UNDEF)
        return false;

    *regs = newRegs;
    procaddr = dwarfGetReg(regs, rar);
#ifdef CFA_RESTORE_REGNO
    // The CFA is defined to be the stack pointer in the calling frame.
    dwarfSetReg(regs, CFA_RESTORE_REGNO, cfa);
#endif
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

