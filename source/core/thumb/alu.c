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
** Implement the ADD instruction (low registers).
*/
void
core_thumb_lo_add(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t rs;
    uint32_t rhs;
    bool immediate;

    core = &gba->core;
    rd = bitfield_get_range(op, 0, 3);
    rs = bitfield_get_range(op, 3, 6);
    immediate = bitfield_get(op, 10);

    if (immediate) {
        rhs = bitfield_get_range(op, 6, 9);
    } else {
        rhs = core->registers[bitfield_get_range(op, 6, 9)];
    }

    core->registers[rd] = core->registers[rs] + rhs;

    core->cpsr.zero = !(core->registers[rd]);
    core->cpsr.negative = bitfield_get(core->registers[rd], 31);
    core->cpsr.carry = uadd32(core->registers[rs], rhs, 0);
    core->cpsr.overflow = iadd32(core->registers[rs], rhs, 0);
}

/*
** Implement the SUB instruction (low registers).
*/
void
core_thumb_lo_sub(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t rs;
    uint32_t rhs;
    bool immediate;

    core = &gba->core;
    rd = bitfield_get_range(op, 0, 3);
    rs = bitfield_get_range(op, 3, 6);
    immediate = bitfield_get(op, 10);

    if (immediate) {
        rhs = bitfield_get_range(op, 6, 9);
    } else {
        rhs = core->registers[bitfield_get_range(op, 6, 9)];
    }

    core->registers[rd] = core->registers[rs] - rhs;

    core->cpsr.zero = !(core->registers[rd]);
    core->cpsr.negative = bitfield_get(core->registers[rd], 31);
    core->cpsr.carry = usub32(core->registers[rs], rhs, 0);
    core->cpsr.overflow = isub32(core->registers[rs], rhs, 0);
}

/*
** Implement the MOV from immediate instruction.
*/
void
core_thumb_mov_imm(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint16_t rd;
    uint32_t imm;

    rd = bitfield_get_range(op, 8, 11);
    imm = bitfield_get_range(op, 0, 8);

    core = &gba->core;
    core->registers[rd] = imm;
    core->cpsr.zero = !(core->registers[rd]);
    core->cpsr.negative = bitfield_get(core->registers[rd], 31); // Useless ?
}

/*
** Implement the Compare Immediate instructions.
*/
void
core_thumb_cmp_imm(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint16_t rd;
    uint32_t imm;
    uint32_t tmp;

    rd = bitfield_get_range(op, 8, 11);
    imm = bitfield_get_range(op, 0, 8);

    core = &gba->core;
    tmp = core->registers[rd] - imm;

    core->cpsr.zero = !tmp;
    core->cpsr.negative = bitfield_get(tmp, 31);
    core->cpsr.carry = usub32(core->registers[rd], imm, 0);
    core->cpsr.overflow = isub32(core->registers[rd], imm, 0);
}

/*
** Implement the ADD immediate instruction.
*/
void
core_thumb_add_imm(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint16_t rd;
    uint32_t imm;

    rd = bitfield_get_range(op, 8, 11);
    imm = bitfield_get_range(op, 0, 8);

    core = &gba->core;
    core->cpsr.carry = uadd32(core->registers[rd], imm, 0);
    core->cpsr.overflow = iadd32(core->registers[rd], imm, 0);

    core->registers[rd] += imm;

    core->cpsr.zero = !(core->registers[rd]);
    core->cpsr.negative = bitfield_get(core->registers[rd], 31);
}

/*
** Implement the SUB immediate instruction.
*/
void
core_thumb_sub_imm(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint16_t rd;
    uint32_t imm;

    rd = bitfield_get_range(op, 8, 11);
    imm = bitfield_get_range(op, 0, 8);

    core = &gba->core;
    core->cpsr.carry = usub32(core->registers[rd], imm, 0);
    core->cpsr.overflow = isub32(core->registers[rd], imm, 0);

    core->registers[rd] -= imm;

    core->cpsr.zero = !(core->registers[rd]);
    core->cpsr.negative = bitfield_get(core->registers[rd], 31);
}

/*
** Implement the ADD from/to High Register instruction.
*/
void
core_thumb_hi_add(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint16_t rd;
    uint16_t rs;
    bool h1;
    bool h2;

    h1 = bitfield_get(op, 7);
    h2 = bitfield_get(op, 6);
    rd = bitfield_get_range(op, 0, 3) + h1 * 8;
    rs = bitfield_get_range(op, 3, 6) + h2 * 8;

    hs_assert(h1 | h2); // Ensure h1 != 0 && h2 != 0, or op is undefined.

    core = &gba->core;
    core->registers[rd] = core->registers[rd] + core->registers[rs];

    if (rd == 15) {
        core_reload_pipeline(gba);
    }
}

/*
** Implement the CMP from/to High Register instruction.
*/
void
core_thumb_hi_cmp(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint16_t rd;
    uint16_t rs;
    bool h1;
    bool h2;
    uint32_t op1;
    uint32_t op2;

    h1 = bitfield_get(op, 7);
    h2 = bitfield_get(op, 6);
    rd = bitfield_get_range(op, 0, 3) + h1 * 8;
    rs = bitfield_get_range(op, 3, 6) + h2 * 8;

    core = &gba->core;
    op1 = core->registers[rd];
    op2 = core->registers[rs];

    hs_assert(h1 | h2); // Ensure h1 != 0 && h2 != 0, or op is undefined.

    core->cpsr.zero = !(op1 - op2);
    core->cpsr.negative = bitfield_get(op1 - op2, 31);
    core->cpsr.carry = usub32(op1, op2, 0);
    core->cpsr.overflow = isub32(op1, op2, 0);
}

/*
** Implement the MOV from/to High Register instruction.
*/
void
core_thumb_hi_mov(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint16_t rd;
    uint16_t rs;
    bool h1;
    bool h2;

    h1 = bitfield_get(op, 7);
    h2 = bitfield_get(op, 6);
    rd = bitfield_get_range(op, 0, 3) + h1 * 8;
    rs = bitfield_get_range(op, 3, 6) + h2 * 8;

    hs_assert(h1 | h2); // Ensure h1 != 0 && h2 != 0, or op is undefined.

    core = &gba->core;
    core->registers[rd] = core->registers[rs];

    if (rd == 15) {
        core->pc &= 0xfffffffe;
        core_reload_pipeline(gba);
    }
}

/*
** Implement the Load address from SP instruction.
*/
void
core_thumb_add_sp_imm(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t offset;
    uint32_t rd;

    offset = bitfield_get_range(op, 0, 8) << 2;
    rd = bitfield_get_range(op, 8, 11);

    core = &gba->core;
    core->registers[rd] = core->sp + offset;
}

/*
** Implement the Load address from PC instruction.
*/
void
core_thumb_add_pc_imm(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t offset;
    uint32_t rd;

    offset = bitfield_get_range(op, 0, 8) << 2;
    rd = bitfield_get_range(op, 8, 11);

    core = &gba->core;
    core->registers[rd] = (core->pc & 0xFFFFFFFC) + offset;
}

/*
** Implement the ADD offset to stack pointer instruction.
*/
void
core_thumb_add_sp_s_imm(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    bool sign;
    uint32_t offset;

    core = &gba->core;
    sign = bitfield_get(op, 7);
    offset = bitfield_get_range(op, 0, 7) << 2;

    if (sign) {
        // Offset is negative
        core->sp -= offset;
    } else {
        // Offset is positive
        core->sp += offset;
    }
}

/*
** Implement a bunch of ALU instructions.
*/
void
core_thumb_alu(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint16_t rd;
    uint16_t rs;
    uint32_t op1;
    uint32_t op2;
    bool carry_out;

    rd = bitfield_get_range(op, 0, 3);
    rs = bitfield_get_range(op, 3, 6);

    core = &gba->core;
    op1 = core->registers[rd];
    op2 = core->registers[rs];

    switch (bitfield_get_range(op, 6, 13)) {
        case 0b0000:
            // AND
            core->registers[rd] = op1 & op2;
            core->cpsr.zero = !(core->registers[rd]);
            core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            break;
        case 0b0001:
            // EOR (XOR)
            core->registers[rd] = op1 ^ op2;
            core->cpsr.zero = !(core->registers[rd]);
            core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            break;
        case 0b0010:
            // LSL (Logical Shift Left)

            op2 &= 0xFF; // Keep only one byte

            switch (op2) {
                case 0:
                    carry_out = core->cpsr.carry;
                    break;
                case 1 ... 32:
                    op1 <<= op2 - 1;
                    carry_out = op1 >> 31;
                    op1 <<= 1;
                    break;
                default:
                    op1 = 0;
                    carry_out = 0;
                    break;
            }

            core->cpsr.carry = carry_out;
            core->cpsr.zero = !op1;
            core->cpsr.negative = bitfield_get(op1, 31);

            core->registers[rd] = op1;
            break;
        case 0b0011:
            // LSR (Logical Shift Right)

            op2 &= 0xFF; // Keep only one byte

            switch (op2) {
                case 0:
                    carry_out = core->cpsr.carry;
                    break;
                case 1 ... 32:
                    op1 >>= op2 - 1;
                    carry_out = op1 & 0b1;
                    op1 >>= 1;
                    break;
                default:
                    op1 = 0;
                    carry_out = 0;
                    break;
            }

            core->cpsr.carry = carry_out;
            core->cpsr.zero = !op1;
            core->cpsr.negative = bitfield_get(op1, 31);

            core->registers[rd] = op1;
            break;
        case 0b0100:
            // ASR (Arithmetic Shift Right)

            op2 &= 0xFF; // Keep only one byte

            switch (op2) {
                case 0:
                    carry_out = core->cpsr.carry;
                    break;
                case 1 ... 32:
                    op1 = (int32_t)op1 >> (op2 - 1);
                    carry_out = op1 & 0b1;
                    op1 = (int32_t)op1 >> 1;
                    break;
                default:
                    carry_out = bitfield_get(op1, 31);
                    op1 = carry_out ? 0xFFFFFFFF : 0;
                    break;
            }

            core->cpsr.carry = carry_out;
            core->cpsr.zero = !op1;
            core->cpsr.negative = bitfield_get(op1, 31);

            core->registers[rd] = op1;
            break;
        case 0b0101:
            // ADC (Add with Carry) (op1 + op2 + carry)
            {
                bool carry;

                carry = core->cpsr.carry;
                core->registers[rd] = op1 + op2 + core->cpsr.carry;
                core->cpsr.zero = (core->registers[rd] == 0);
                core->cpsr.negative = ((core->registers[rd] & 0x80000000) != 0);
                core->cpsr.carry = uadd32(op1, op2, carry);
                core->cpsr.overflow = iadd32(op1, op2, carry);
            }
            break;
        case 0b0110:
            // SBC (Sub with carry) (op1 - op2 + carry - 1)
            {
                bool carry;

                carry = core->cpsr.carry;
                core->registers[rd] = op1 - op2 + core->cpsr.carry - 1;
                core->cpsr.zero = !(core->registers[rd]);
                core->cpsr.negative = bitfield_get(core->registers[rd], 31);
                core->cpsr.carry = usub32(op1, op2, !carry);
                core->cpsr.overflow = isub32(op1, op2, !carry);
            }
            break;
        case 0b0111:
            // ROR (Rotate Right)
            op2 &= 0xFF; // Keep only one byte

            if (op2 > 32) {
                op2 %= 32;
            }

            switch (op2) {
                case 0:
                    carry_out = core->cpsr.carry;
                    break;
                case 1 ... 31:
                    carry_out = (op1 >> (op2 - 1)) & 0b1;
                    op1 = ror32(op1, op2);
                    break;
                case 32:
                    carry_out = (op1 >> 31) & 0b1;
                    break;
            }

            core->cpsr.carry = carry_out;
            core->cpsr.zero = !op1;
            core->cpsr.negative = bitfield_get(op1, 31);

            core->registers[rd] = op1;
            break;
        case 0b1000:
            // TST (as AND, but result is not written)
            core->cpsr.zero = !(op1 & op2);
            core->cpsr.negative = bitfield_get(op1 & op2, 31);
            break;
        case 0b1001:
            // NEG (As 0 - op2, implemented as RSBS Rd, Rs, #0)
            core->registers[rd] = 0 - op2;
            core->cpsr.zero = !(core->registers[rd]);
            core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            core->cpsr.carry = usub32(0, op2, 0);
            core->cpsr.overflow = isub32(0, op2, 0);
            break;
        case 0b1010:
            // CMP (as SUB, but result is not written)
            core->cpsr.zero = !(op1 - op2);
            core->cpsr.negative = bitfield_get(op1 - op2, 31);
            core->cpsr.carry = usub32(op1, op2, 0);
            core->cpsr.overflow = isub32(op1, op2, 0);
            break;
        case 0b1011:
            // CMN (as ADD, but result is not written)
            core->cpsr.zero = !(op1 + op2);
            core->cpsr.negative = bitfield_get(op1 + op2, 31);
            core->cpsr.carry = uadd32(op1, op2, 0);
            core->cpsr.overflow = iadd32(op1, op2, 0);
            break;
        case 0b1100:
            // ORR (Logical OR)
            core->registers[rd] = op1 | op2;
            core->cpsr.zero = !(core->registers[rd]);
            core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            break;
        case 0b1101:
            core->registers[rd] = op1 * op2;
            core->cpsr.zero = !(core->registers[rd]);
            core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            break;
        case 0b1110:
            // BIC (op1 AND NOT op2)
            core->registers[rd] = op1 & ~op2;
            core->cpsr.zero = !(core->registers[rd]);
            core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            break;
        case 0b1111:
            // MVN (NOT op2, op1 is ignored)
            core->registers[rd] = ~op2;
            core->cpsr.zero = !(core->registers[rd]);
            core->cpsr.negative = bitfield_get(core->registers[rd], 31);
            break;
    }
}
