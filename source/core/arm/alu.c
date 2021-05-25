/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba.h"

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

    rd = (op >> 12) & 0xF;
    rn = (op >> 16) & 0xF;
    cond = bitfield_get(op, 20);

    core = &gba->core;
    op1 = core->registers[rn];
    op2 = 0;

    /*
    ** The second operand is either an immediate value or obtained through
    ** anoter register, possible shifted.
    */
    if (bitfield_get(op, 25)) { // Immediate
        uint32_t imm;
        uint32_t rot;

        imm = op & 0xFF;
        rot = (op >> 8) & 0xF;
        rot *= 2;
        op2 = (imm >> rot) | (imm << (32 - rot));
    } else { // Register
        uint32_t rm;
        uint32_t shift;

        rm = op & 0xF;
        shift = (op >> 4) & 0xFF;
        op2 = core_compute_shift(core, shift, core->registers[rm], cond && rd != 15);
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
            }
            break;
        case 1: // EOR (op1 XOR op2)
            core->registers[rd] = op1 ^ op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            }
            break;
        case 2: // SUB (op1 - op2)
            core->registers[rd] = op1 - op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = usub32(op1, op2);
                core->cpsr.overflow = isub32(op1, op2);
            }
            break;
        case 3: // RSB (op2 - op1)
            core->registers[rd] = op2 - op1;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = usub32(op2, op1);
                core->cpsr.overflow = isub32(op2, op1);
            }
            break;
        case 4: // ADD (op1 + op2)
            core->registers[rd] = op1 + op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = uadd32(op1, op2);
                core->cpsr.overflow = iadd32(op1, op2);
            }
            break;
        case 5: // ADC (op1 + op2 + carry)
            core->registers[rd] = op1 + op2 + core->cpsr.carry;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = uadd32(op1, op2);
                core->cpsr.carry |= uadd32(op1 + op2, core->cpsr.carry);
                core->cpsr.overflow = iadd32(op1, op2);
                core->cpsr.overflow = iadd32(op1 + op2, core->cpsr.carry);
            }
            break;
        case 6: // SBC (op1 - op2 + carry - 1)
            core->registers[rd] = op1 - op2 + core->cpsr.carry - 1;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = usub32(op1, op2);
                core->cpsr.carry |= uadd32(op1 - op2, core->cpsr.carry);
                core->cpsr.carry |= usub32(op1 - op2 + core->cpsr.carry, 1);
                core->cpsr.overflow = isub32(op1, op2);
                core->cpsr.overflow = iadd32(op1 - op2, core->cpsr.carry);
                core->cpsr.overflow |= isub32(op1 - op2 + core->cpsr.carry, 1);
            }
            break;
        case 7: // RSC (op2 - op1 + carry - 1)
            core->registers[rd] = op2 - op1 + core->cpsr.carry - 1;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = usub32(op2, op1);
                core->cpsr.carry |= uadd32(op2 - op1, core->cpsr.carry);
                core->cpsr.carry |= usub32(op2 - op1 + core->cpsr.carry, 1);
                core->cpsr.overflow = isub32(op2, op1);
                core->cpsr.overflow = iadd32(op2 - op1, core->cpsr.carry);
                core->cpsr.overflow |= isub32(op2 - op1 + core->cpsr.carry, 1);
            }
            break;
        case 8: // TST (as AND, but result is not written)
            core->cpsr.zero = !(op1 & op2);
            core->cpsr.negative = bitfield_get(op1 & op2, 31);
            break;
        case 9: // TEQ (as EOR, but result is not written)
            core->cpsr.zero = !(op1 ^ op2);
            core->cpsr.negative = bitfield_get(op1 ^ op2, 31);
            break;
        case 10: // CMP (as SUB, but result is not written)
            if (cond && rd != 15) {
                core->cpsr.zero = !(op1 - op2);
                core->cpsr.negative = bitfield_get(op1 - op2, 31);
                core->cpsr.carry = usub32(op1, op2);
                core->cpsr.overflow = isub32(op1, op2);
            }
            break;
        case 11: // CMN (as ADD, but result is not written)
            if (cond && rd != 15) {
                core->cpsr.zero = !(op1 + op2);
                core->cpsr.negative = bitfield_get(op1 + op2, 31);
                core->cpsr.carry = uadd32(op1, op2);
                core->cpsr.overflow = iadd32(op1, op2);
            }
            break;
        case 12: // ORR (op1 OR op2)
            core->registers[rd] = op1 | op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            }
            break;
        case 13: // MOV (op2, op1 is ignored)
            core->registers[rd] = op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            }
            break;
        case 14: // BIC (op1 AND NOT op2)
            core->registers[rd] = op1 & ~op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            }
            break;
        case 15: // MVN (NOT op2, op1 is ignored)
            core->registers[rd] = ~op2;
            if (cond && rd != 15) {
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            }
            break;
        default:
            break;
    }
}
