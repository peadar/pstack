DWARF_CFA_INSN(DW_CFA_advance_loc, 0x40)
DWARF_CFA_INSN(DW_CFA_offset, 0x80)
DWARF_CFA_INSN(DW_CFA_restore, 0xc0)
DWARF_CFA_INSN(DW_CFA_nop, 0)
DWARF_CFA_INSN(DW_CFA_set_loc, 1)
DWARF_CFA_INSN(DW_CFA_advance_loc1, 0x02)
DWARF_CFA_INSN(DW_CFA_advance_loc2, 0x03)
DWARF_CFA_INSN(DW_CFA_advance_loc4, 0x04)
DWARF_CFA_INSN(DW_CFA_offset_extended, 0x05)
DWARF_CFA_INSN(DW_CFA_restore_extended, 0x06)
DWARF_CFA_INSN(DW_CFA_undefined, 0x07)
DWARF_CFA_INSN(DW_CFA_same_value, 0x08)
DWARF_CFA_INSN(DW_CFA_register, 0x09)
DWARF_CFA_INSN(DW_CFA_remember_state, 0x0a)
DWARF_CFA_INSN(DW_CFA_restore_state, 0x0b)
DWARF_CFA_INSN(DW_CFA_def_cfa, 0x0c)
DWARF_CFA_INSN(DW_CFA_def_cfa_register, 0x0d)
DWARF_CFA_INSN(DW_CFA_def_cfa_offset, 0x0e)
DWARF_CFA_INSN(DW_CFA_def_cfa_expression, 0x0f)

    // DWARF 3 only {
DWARF_CFA_INSN(DW_CFA_expression, 0x10)
DWARF_CFA_INSN(DW_CFA_offset_extended_sf, 0x11)
DWARF_CFA_INSN(DW_CFA_def_cfa_sf, 0x12)
DWARF_CFA_INSN(DW_CFA_def_cfa_offset_sf, 0x13)
DWARF_CFA_INSN(DW_CFA_val_offset, 0x14)
DWARF_CFA_INSN(DW_CFA_val_offset_sf, 0x15)
DWARF_CFA_INSN(DW_CFA_val_expression, 0x16)
    // }

DWARF_CFA_INSN(DW_CFA_lo_user, 0x1c)
#ifdef __aarch64__
DWARF_CFA_INSN(DW_CFA_AARCH64_negate_ra_state, 0x2d)
#else
DWARF_CFA_INSN(DW_CFA_GNU_window_save, 0x2d)
#endif

DWARF_CFA_INSN(DW_CFA_GNU_args_size, 0x2e)
DWARF_CFA_INSN(DW_CFA_GNU_negative_offset_extended, 0x2f)
DWARF_CFA_INSN(DW_CFA_hi_user, 0x3f)
