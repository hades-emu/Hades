/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

/*
** References:
**   * ARM7TDMI-S Data Sheet
**      https://vision.gel.ulaval.ca/~jflalonde/cours/1001/h17/docs/arm-instructionset.pdf
**
*/

#include <stdbool.h>
#include "hades.h"
#include "core.h"

/*
** Fetch, decode and execute the next instruction.
*/
void
core_next_op(
    struct core *core
) {
    uint32_t op;
    bool can_exec;

    op = core_mem_read32(core, core->r15);
    core->r15 += 4;

    //printf("[CPU] Decoding %#08x\n", op->value);

    // Test if the conditions required to execute the instruction are met
    switch (op >> 28) {
        case COND_EQ: can_exec = bitfield_get(core->cpsr, CPSR_Z); break;
        case COND_NE: can_exec = !bitfield_get(core->cpsr, CPSR_Z); break;
        case COND_CS: can_exec = bitfield_get(core->cpsr, CPSR_C); break;
        case COND_CC: can_exec = !bitfield_get(core->cpsr, CPSR_C); break;
        case COND_MI: can_exec = bitfield_get(core->cpsr, CPSR_N); break;
        case COND_PL: can_exec = !bitfield_get(core->cpsr, CPSR_N); break;
        case COND_VS: can_exec = bitfield_get(core->cpsr, CPSR_V); break;
        case COND_VC: can_exec = !bitfield_get(core->cpsr, CPSR_V); break;
        case COND_HI: can_exec = bitfield_get(core->cpsr, CPSR_C) && !bitfield_get(core->cpsr, CPSR_Z); break;
        case COND_LS: can_exec = !bitfield_get(core->cpsr, CPSR_C) || bitfield_get(core->cpsr, CPSR_Z); break;
        case COND_GE: can_exec = bitfield_get(core->cpsr, CPSR_N) == bitfield_get(core->cpsr, CPSR_V); break;
        case COND_LT: can_exec = bitfield_get(core->cpsr, CPSR_N) != bitfield_get(core->cpsr, CPSR_V); break;
        case COND_GT: can_exec = !bitfield_get(core->cpsr, CPSR_Z) && (bitfield_get(core->cpsr, CPSR_N) == bitfield_get(core->cpsr, CPSR_V));break;
        case COND_LE: can_exec = bitfield_get(core->cpsr, CPSR_Z) || (bitfield_get(core->cpsr, CPSR_N) != bitfield_get(core->cpsr, CPSR_V)); break;
        case COND_AL: can_exec = true; break;
        default:
            panic(CORE, "Unknown cond %u\n", op >> 28);
    }

    // Ignore instructions where the conditions aren't met.
    if (!can_exec) {
        return ;
    }

    switch ((op >> 25) & 0b111) {
        case 0:
        case 1:
            if ((op & 0xFFFFFF0) == 0x12FFF10) {
                core_branchxchg(core, op);
            } else if (bitfield_get(op, 25) || !bitfield_get(op, 7) || !bitfield_get(op, 4)) {
                core_data_processing(core, op);
            } else {
                panic(CORE, "Unknown instruction");
            }
            break;
        case 2:
        case 3:
            // Undefined if bit 25 and 4 are set
            if (bitfield_get(op, 25) && bitfield_get(op, 4)) {
                panic(CORE, "Undefined state");
            }

            core_sdt(core, op);
            break;
        case 5:
            core_branch(core, op);
            break;
        default:
            panic(CORE, "Unknown instruction");
            break;
    }
}

/*
** Update the carry flag of the CPSR.
*/
void
core_cpsr_update_carry(
    struct core *core,
    bool carry
) {
    if (carry != bitfield_get(core->cpsr, CPSR_C)) {
        hs_logln(DEBUG, "CPSR: carry flag %s", carry ? "set" : "unset");
        bitfield_update(&core->cpsr, CPSR_C, carry);
    }
}

/*
** Update the thumb flag of the CPSR.
*/
void
core_cpsr_update_thumb(
    struct core *core,
    bool thumb
) {
    if (thumb != bitfield_get(core->cpsr, CPSR_THUMB)) {
        hs_logln(DEBUG, "CPSR: thumb flag %s", thumb ? "set" : "unset");
        bitfield_update(&core->cpsr, CPSR_THUMB, thumb);
    }
}

/*
** Update the zero and negative flag of the CPSR.
*/
void
core_cpsr_update_zn(
    struct core *core,
    uint32_t val
) {
    bool z;
    bool n;

    z = (val == 0);
    n = ((val & 0x80000000) != 0);

    if (z != bitfield_get(core->cpsr, CPSR_Z)) {
        hs_logln(DEBUG, "CPSR: zero flag %s", z ? "set" : "unset");
        bitfield_update(&core->cpsr, CPSR_Z, z);
    }

    if (n != bitfield_get(core->cpsr, CPSR_N)) {
        hs_logln(DEBUG, "CPSR: negative flag %s", n ? "set" : "unset");
        bitfield_update(&core->cpsr, CPSR_N, n);
    }
}

/*
** Update the overflow flag of the CPSR.
*/
void
core_cpsr_update_overflow(
    struct core *core,
    bool overflow
) {
    if (overflow != bitfield_get(core->cpsr, CPSR_V)) {
        hs_logln(DEBUG, "CPSR: overflow flag %s", overflow ? "set" : "unset");
        bitfield_update(&core->cpsr, CPSR_V, overflow);
    }
}

/*
** Compute the operand of an instruction that uses an encoded shift register.
** If `update_carry` is true, this will set the carry flag of the CPSR to its
** correct value.
*/
uint32_t
compute_shift(
    struct core *core,
    uint32_t encoded_shift,
    uint32_t value,
    bool update_carry
){
    uint32_t type;
    uint32_t bits;
    bool carry_out;

    /*
    ** The first bit tells us if the amount of bits to shift is either stored as
    ** an immediate value or within a register.
    */
    if (bitfield_get(encoded_shift, 0)) {   // Register
        uint32_t rs;

        rs = (encoded_shift >> 4) & 0xF;
        bits = core->registers[rs] & 0xFF;

        /*
        ** The spec requires a bit of error handling regarding register
        ** specified shift amount.
        */

        if (bits == 0) {
            return (value);
        } else if (bits >= 32) {
            unimplemented(CORE, "unsupported shifts of more than 32 bits");
        }

    } else {                                // Immediate value
        bits = (encoded_shift >> 3) & 0x1F;
    }

    type = (encoded_shift >> 1) & 0b11;
    carry_out = 0;

    /*
    ** There's four kind of shifts: logical left, logicial right, arithmetic
    ** right and rotate right.
    */
    switch (type) {
        // Logical left
        case 0:
            /*
            ** If LSL#0 then the carry bit is the old content of the CPSR C flag
            ** and the value is left untouched.
            */
            if (bits == 0) {
                carry_out = bitfield_get(core->cpsr, CPSR_C);
            } else {
                value <<= bits - 1;
                carry_out = value >> 31;                    // Save the carry
                value <<= 1;
            }
            break;
        // Logical right
        case 1:
            // LSR#0 is used to encode LSR#32
            if (bits == 0) {
                bits = 32;
            }
            value >>= bits - 1;
            carry_out = value & 0b1;                        // Save the carry
            value >>= 1;
            break;
        // Arithmetic right
        case 2:
            // ASR#0 is used to encode ASR#32
            if (bits == 0) {
                bits = 32;
            }
            value = (int32_t)value >> (bits - 1);
            carry_out = value & 0b1;                        // Save the carry
            value = (int32_t)value >> 1;
            break;
        // Rotate right
        case 3:
            // ROR#0 is used to encode RRX
            if (bits == 0) {
                carry_out = value & 0b1;
                value >>= 1;
                value |= bitfield_get(core->cpsr, CPSR_C) << 31;
            } else {
                carry_out = (value >> (bits - 1)) & 0b1;    // Save the carry
                value = (value >> bits) | (value << (32 - bits));
            }
            break;
    }

    if (update_carry) {
        core_cpsr_update_carry(core, carry_out);
    }

    return (value);
}
