/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba/gba.h"
#include "gba/core/helpers.h"

/*
** Execute the Data Processing instructions (ADD, SUB, MOV, etc.).
*/
void
core_arm_alu(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t rn;
    uint32_t op1;
    uint32_t op2;
    bool cond;
    bool early_pc_inc;
    bool shift_carry;

    early_pc_inc = false;
    rd = (op >> 12) & 0xF;
    rn = (op >> 16) & 0xF;
    cond = bitfield_get(op, 20);

    core = &gba->core;
    core->prefetch_access_type = SEQUENTIAL;
    shift_carry = core->cpsr.carry;

    /*
    ** The second operand is either an immediate value or obtained through
    ** anoter register, possibly shifted.
    */
    if (bitfield_get(op, 25)) { // Immediate
        bool carry_out;
        uint32_t rot;

        op1 = core->registers[rn];
        op2 = bitfield_get_range(op, 0, 8);
        rot = bitfield_get_range(op, 8, 12) * 2;
        if (rot > 0) {
            carry_out = (op2 >> (rot - 1)) & 0b1;
            op2 = ror32(op2, rot);

            // Update the carry flag
            if (cond && rd != 15) {
                shift_carry = carry_out;
            }
        }
    } else { // Register
        uint32_t rm;
        uint32_t shift;

        rm = op & 0xF;
        shift = (op >> 4) & 0xFF;

        /*
        ** If R15 (the PC) is used as an operand in a data processing instruction the register is used directly.
        ** The PC value will be the address of the instruction, plus 8 or 12 bytes due to instruction prefetching.
        **   - If the shift amount is specified in the instruction, the PC will be 8 bytes ahead.
        **   - If a register is used to specify the shift amount the PC will be 12 bytes ahead
        */
        if (bitfield_get(shift, 0)) {
            early_pc_inc = true;
            core->pc += 4;
            core_idle(gba);
            core->prefetch_access_type = NON_SEQUENTIAL;
        }

        op1 = core->registers[rn];
        op2 = core_compute_shift(core, shift, core->registers[rm], (cond && rd != 15 ? &shift_carry : NULL));
    }

    /*
    ** Execute the correct data processing instruction.
    */
    switch ((op >> 21) & 0xF) {
        case 0: // AND (op1 AND op2)
            core->registers[rd] = op1 & op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = shift_carry;
            }
            break;
        case 1: // EOR (op1 XOR op2)
            core->registers[rd] = op1 ^ op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = shift_carry;
            }
            break;
        case 2: // SUB (op1 - op2)
            core->registers[rd] = op1 - op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = usub32(op1, op2, 0);
                core->cpsr.overflow = isub32(op1, op2, 0);
            }
            break;
        case 3: // RSB (op2 - op1)
            core->registers[rd] = op2 - op1;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = usub32(op2, op1, 0);
                core->cpsr.overflow = isub32(op2, op1, 0);
            }
            break;
        case 4: // ADD (op1 + op2)
            core->registers[rd] = op1 + op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = uadd32(op1, op2, 0);
                core->cpsr.overflow = iadd32(op1, op2, 0);
            }
            break;
        case 5: // ADC (op1 + op2 + carry)
            core->registers[rd] = op1 + op2 + core->cpsr.carry;
            if (cond && rd != 15) {
                bool carry;

                carry = core->cpsr.carry;
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = uadd32(op1, op2, carry);
                core->cpsr.overflow = iadd32(op1, op2, carry);
            }
            break;
        case 6: // SBC (op1 - op2 - !carry)
            core->registers[rd] = op1 - op2 - !core->cpsr.carry;
            if (cond && rd != 15) {
                bool carry;

                carry = core->cpsr.carry;
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = usub32(op1, op2, !carry);
                core->cpsr.overflow = isub32(op1, op2, !carry);
            }
            break;
        case 7: // RSC (op2 - op1 - !carry)
            core->registers[rd] = op2 - op1 - !core->cpsr.carry;
            if (cond && rd != 15) {
                bool carry;

                carry = core->cpsr.carry;
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = usub32(op2, op1, !carry);
                core->cpsr.overflow = isub32(op2, op1, !carry);
            }
            break;
        case 8: // TST (as AND, but result is not written)
            core->cpsr.zero = !(op1 & op2);
            core->cpsr.negative = bitfield_get(op1 & op2, 31);
            core->cpsr.carry = shift_carry;
            break;
        case 9: // TEQ (as EOR, but result is not written)
            core->cpsr.zero = !(op1 ^ op2);
            core->cpsr.negative = bitfield_get(op1 ^ op2, 31);
            core->cpsr.carry = shift_carry;
            break;
        case 10: // CMP (as SUB, but result is not written)
            if (cond && rd != 15) {
                core->cpsr.zero = !(op1 - op2);
                core->cpsr.negative = bitfield_get(op1 - op2, 31);
                core->cpsr.carry = usub32(op1, op2, 0);
                core->cpsr.overflow = isub32(op1, op2, 0);
            }
            break;
        case 11: // CMN (as ADD, but result is not written)
            if (cond && rd != 15) {
                core->cpsr.zero = !(op1 + op2);
                core->cpsr.negative = bitfield_get(op1 + op2, 31);
                core->cpsr.carry = uadd32(op1, op2, 0);
                core->cpsr.overflow = iadd32(op1, op2, 0);
            }
            break;
        case 12: // ORR (op1 OR op2)
            core->registers[rd] = op1 | op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = shift_carry;
            }
            break;
        case 13: // MOV (op2, op1 is ignored)
            core->registers[rd] = op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = shift_carry;
            }
            break;
        case 14: // BIC (op1 AND NOT op2)
            core->registers[rd] = op1 & ~op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = shift_carry;
            }
            break;
        case 15: // MVN (NOT op2, op1 is ignored)
            core->registers[rd] = ~op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = shift_carry;
            }
            break;
        default:
            break;
    }

    if (rd == 15) {

        /*
        ** When Rd is R15 and the S flag is set the result of the operation is placed
        ** in R15 and the SPSR corresponding to the current mode is moved to the CPSR.
        */
        if (cond) {
            struct psr new_cpsr;

            new_cpsr = core_spsr_get(core, core->cpsr.mode);
            core_switch_mode(core, new_cpsr.mode);
            core->cpsr = new_cpsr;
        }

        // Read-Only operations do not flush the pipeline
        switch ((op >> 21) & 0xF) {
            case 8: // TST
            case 9: // TEQ
            case 10: // CMP
            case 11: // CMN
                if (!early_pc_inc) {
                    core->pc += 4;
                }
                break;
            default:
                core_reload_pipeline(gba);
                break;
        }
    } else if (!early_pc_inc) {
        core->pc += 4;
    }
}
