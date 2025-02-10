
namespace pstack::Dwarf {

// Execute a set of call frame instructions, updating the CallFrame data and/or
// the current address as we go, and call "yield" just before executing the
// next instruction. This allows for the caller to exit the execution early, or
// observe the progress of the execution

template <typename YieldFunc>
CallFrame
CIE::execInsns(const CallFrame &dframe, uintptr_t start, uintptr_t end, uintmax_t addr, YieldFunc yield) const {
    DWARFReader r( frameInfo->io, start, end );
    std::stack<CallFrame> stack;
    CallFrame frame = dframe;

    while (!yield(addr, frame) && ! r.empty()) {
        uint8_t rawOp = r.getu8();
        int reg = rawOp &0x3f;
        auto op = CFAInstruction(rawOp & ~0x3f);
        switch (op) {
        case DW_CFA_advance_loc:
            addr += reg * codeAlign;
            break;

        case DW_CFA_offset: {
            intmax_t offset = r.getsleb128();
            frame.registers[reg].type = OFFSET;
            frame.registers[reg].u.offset = offset * dataAlign;
            break;
        }

        case DW_CFA_restore: {
            frame.registers[reg] = dframe.registers.at(reg);
            break;
        }

        case 0:
            op = CFAInstruction(rawOp & 0x3f);
            switch (op) {
            case DW_CFA_nop:
                break;

            case DW_CFA_set_loc:
                addr = r.getuint(r.addrLen);
                break;

            case DW_CFA_advance_loc1:
                addr += r.getu8() * codeAlign;
                break;

            case DW_CFA_advance_loc2:
                addr += r.getu16() * codeAlign;
                break;

            case DW_CFA_advance_loc4:
                addr += r.getu32() * codeAlign;
                break;

            case DW_CFA_offset_extended: {
                auto reg = r.getuleb128();
                auto offset = r.getuleb128();
                frame.registers[reg].type = OFFSET;
                frame.registers[reg].u.offset = offset * dataAlign;
                break;
            }

            case DW_CFA_restore_extended:
                reg = r.getuleb128();
                frame.registers[reg] = dframe.registers.at(reg);
                break;

            case DW_CFA_undefined:
                reg = r.getuleb128();
                frame.registers[reg].type = UNDEF;
                break;

            case DW_CFA_same_value:
                reg = r.getuleb128();
                frame.registers[reg].type = SAME;
                break;

            case DW_CFA_register: {
                auto reg1 = r.getuleb128();
                auto reg2 = r.getuleb128();
                frame.registers[reg1].type = REG;
                frame.registers[reg1].u.reg = reg2;
                break;
            }

            case DW_CFA_remember_state:
                stack.push(frame);
                break;

            case DW_CFA_restore_state:
                frame = stack.top();
                stack.pop();
                break;

            case DW_CFA_def_cfa:
                frame.cfaReg = r.getuleb128();
                frame.cfaValue.type = OFFSET;
                frame.cfaValue.u.offset = r.getuleb128();
                break;

            case DW_CFA_def_cfa_sf:
                frame.cfaReg = r.getuleb128();
                frame.cfaValue.type = OFFSET;
                frame.cfaValue.u.offset = r.getsleb128() * dataAlign;
                break;

            case DW_CFA_def_cfa_register:
                frame.cfaReg = r.getuleb128();
                frame.cfaValue.type = OFFSET;
                break;

            case DW_CFA_def_cfa_offset:
                frame.cfaValue.type = OFFSET;
                frame.cfaValue.u.offset = r.getuleb128();
                break;

            case DW_CFA_def_cfa_offset_sf:
                frame.cfaValue.type = OFFSET;
                frame.cfaValue.u.offset = r.getsleb128() * dataAlign;
                break;

            case DW_CFA_val_expression: {
                reg = r.getuleb128();
                auto &unwind = frame.registers[reg];
                unwind.type = VAL_EXPRESSION;
                unwind.u.expression.length = r.getuleb128();
                unwind.u.expression.offset = r.getOffset();
                r.skip(unwind.u.expression.length);
                break;
            }

            case DW_CFA_expression: {
                reg = r.getuleb128();
                auto offset = r.getuleb128();
                auto &unwind = frame.registers[reg];
                unwind.type = EXPRESSION;
                unwind.u.expression.offset = r.getOffset();
                unwind.u.expression.length = offset;
                r.skip(offset);
                break;
            }

            case DW_CFA_def_cfa_expression: {
                frame.cfaValue.type = EXPRESSION;
                auto offset = r.getuleb128();
                frame.cfaValue.u.expression.length = offset;
                frame.cfaValue.u.expression.offset = r.getOffset();
                r.skip(frame.cfaValue.u.expression.length);
                break;
            }

            case DW_CFA_GNU_args_size: {
                r.getsleb128(); // Offset.
                // XXX: We don't do anything with this for the moment.
                break;
            }

            // Can't deal with anything else yet.
            case DW_CFA_GNU_window_save:
            case DW_CFA_GNU_negative_offset_extended:
            default:
                throw (Exception() << "unhandled secondary CFA instruction " << op);
            }
            break;

        default:
            throw (Exception() << "unhandled CFA instruction " << op);
        }
    }
    return frame;
}
}
