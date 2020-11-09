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
#include <string.h>
#include "hades.h"
#include "core.h"

/*
** Initialize the core by attaching the given memory to it
** and initializing its registers.
*/
void
core_init(
    struct core *core,
    uint8_t *mem,
    size_t mem_size
) {
    memset(core, 0, sizeof(*core));
    core->memory = mem;
    core->memory_size = mem_size;
    core_reset(core);
}

/*
** Reset the core and the memory to their default values.
*/
void
core_reset(
    struct core *core
) {
    int i;

    for (i = 0; i < 16; ++i) {
        core->registers[i] = 0;
    }

    core->pc = 0x8000000;      // Entry point of the game
    core->cpsr.raw = 0;
    core->cpsr.mode = MODE_SYSTEM;
    core->big_endian = false;
    core_reload_pipeline(core);
}

/*
** Fetch, decode and execute instructions until the computer catches fire.
*/
void
core_run(
    struct core *core
) {
    while (true) {
        core_step(core);
    }
}

/*
** Fetch, decode and execute the next ARM instruction.
*/
static
void
core_step_arm(
    struct core *core
) {
    uint32_t op;
    bool can_exec;


    op = core->prefetch;
    core->prefetch = core_bus_read32(core, core->pc);
    core->pc += 4;

    can_exec = core_compute_cond(core, op >> 28);

    // Test if the conditions required to execute the instruction are met
    // Ignore instructions where the conditions aren't met.
    if (!can_exec) {
        return ;
    }

    switch (bitfield_get_range(op, 25, 28)) {
        case 0:
        case 1:
            if (bitfield_get_range(op, 4, 28) == 0x12FFF1) {
                core_arm_branchxchg(core, op);
            } else if (bitfield_get_range(op, 23, 25) == 0b10 && bitfield_get_range(op, 16, 22) == 0b001111) {
                core_arm_mrs(core, op);
            } else if (bitfield_get_range(op, 23, 25) == 0b10 && bitfield_get_range(op, 12, 22) == 0b1010011111) {
                core_arm_msr(core, op);
            } else if (bitfield_get_range(op, 23, 25) == 0b10 && bitfield_get_range(op, 12, 22) == 0b1010001111) {
                core_arm_msrf(core, op);
            } else if (!bitfield_get(op, 4) || !bitfield_get(op, 7)) {
                core_arm_alu(core, op);
            } else if (bitfield_get_range(op, 22, 24) == 0) {
                core_arm_mul(core, op);
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
            core_arm_sdt(core, op);
            break;
        case 5:
            core_arm_branch(core, op);
            break;
        default:
            panic(CORE, "Unknown ARM instruction");
            break;
    }
}

/*
** Fetch, decode and execute the next Thumb instruction.
*/
static
void
core_step_thumb(
    struct core *core
) {
    uint16_t op;

    op = core->prefetch;
    core->prefetch = core_bus_read16(core, core->pc);
    core->pc += 2;

    switch (bitfield_get_range(op, 13, 16)) {
        case 0b000:
            switch (bitfield_get_range(op, 11, 13)) {
                case 0b00:
                    core_thumb_lsl(core, op);
                    break;
                case 0b01:
                    core_thumb_lsr(core, op);
                    break;
                case 0b10:
                    core_thumb_asr(core, op);
                    break;
                case 0b11:
                    if (bitfield_get(op, 9)) {
                        core_thumb_sub(core, op);
                    } else {
                        core_thumb_add(core, op);
                    }
                    break;
            }
            break;
        case 0b001:
            switch bitfield_get_range(op, 11, 13) {
                case 0b00:
                    core_thumb_mov_imm(core, op);
                    break;
                case 0b01:
                    core_thumb_cmp_imm(core, op);
                    break;
                case 0b10:
                    core_thumb_add_imm(core, op);
                    break;
                case 0b11:
                    core_thumb_sub_imm(core, op);
                    break;
            }
            break;
        case 0b010:
            if (bitfield_get_range(op, 10, 13) == 0b000) {
                core_thumb_alu(core, op);
            } else if (bitfield_get_range(op, 8, 13) == 0b00100) {
                core_thumb_add_reg(core, op);
            } else if (bitfield_get_range(op, 8, 13) == 0b00101) {
                core_thumb_cmp_reg(core, op);
            } else if (bitfield_get_range(op, 8, 13) == 0b00110) {
                core_thumb_mov_reg(core, op);
            } else if (bitfield_get_range(op, 8, 13) == 0b00111) {
                core_thumb_branchxchg(core, op);
            } else if (bitfield_get_range(op, 11, 13) == 0b01) {
                core_thumb_ldr_pc(core, op);
            } else if (bitfield_get(op, 9)) {
                core_thumb_sdt_reg(core, op);
            } else {
                core_thumb_sdt_sign_halfword(core, op);
            }
            break;
        case 0b011:
            core_thumb_sdt_imm(core, op);
            break;
        case 0b100:
            if (bitfield_get(op, 12)) {
                core_thumb_sdt_sp(core, op);
            } else {
                core_thumb_sdt_halfword(core, op);
            }
            break;
        case 0b101:
            if (bitfield_get_range(op, 11, 13) == 0b00) {
                core_thumb_add_from_pc(core, op);
            } else if (bitfield_get_range(op, 11, 13) == 0b01) {
                core_thumb_add_from_sp(core, op);
            } else if (bitfield_get_range(op, 8, 12) == 0) {
                core_thumb_add_sp(core, op);
            } else {
                if (bitfield_get(op, 11)) {
                    core_thumb_pop(core, op);
                } else {
                    core_thumb_push(core, op);
                }
            }
            break;
        case 0b110:
            if (bitfield_get(op, 12)) {
                core_thumb_branch_cond(core, op);
            } else {
                goto unknown_op;
            }
            break;
        case 0b111:
            if (bitfield_get(op, 12)) {
                core_thumb_branchlink(core, op);
            } else if (!bitfield_get(op, 11)) {
                core_thumb_branch(core, op);
            } else {
                goto unknown_op;
            }
            break;
        default:
unknown_op:
            panic(CORE, "Unknown thumb instruction. Opcode: 0x%04x", op);
            break;
    }
}

/*
** Fetch, decode and execute the next instruction.
*/
void
core_step(
    struct core *core
) {
    static size_t count = 0;

    printf("Executing instruction %zu...\n", ++count);

    if (core->cpsr.thumb) {
        core_step_thumb(core);
    } else {
        core_step_arm(core);
    }
}

/*
** Reload the cached op-code on the 3-stage pipeline.
** This must be called when the value of PC is changed.
*/
void
core_reload_pipeline(
    struct core *core
) {
    if (core->cpsr.thumb) {
        core->prefetch = core_bus_read16(core, core->pc);
        core->pc += 2;
    } else {
        core->prefetch = core_bus_read32(core, core->pc);
        core->pc += 4;
    }
}

/*
** Compute the operand of an instruction that uses an encoded shift register.
** If `update_carry` is true, this will set the carry flag of the CPSR to its
** correct value.
*/
uint32_t
core_compute_shift(
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
                carry_out = core->cpsr.carry;
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
                value |= core->cpsr.carry << 31;
            } else {
                carry_out = (value >> (bits - 1)) & 0b1;    // Save the carry
                value = (value >> bits) | (value << (32 - bits));
            }
            break;
    }

    if (update_carry) {
        core->cpsr.carry = carry_out;
    }

    return (value);
}

bool
core_compute_cond(
    struct core *core,
    uint32_t cond
) {
    switch (cond) {
        case COND_EQ: return core->cpsr.zero;
        case COND_NE: return !core->cpsr.zero;
        case COND_CS: return core->cpsr.carry;
        case COND_CC: return !core->cpsr.carry;
        case COND_MI: return core->cpsr.negative;
        case COND_PL: return !core->cpsr.negative;
        case COND_VS: return core->cpsr.overflow;
        case COND_VC: return !core->cpsr.overflow;
        case COND_HI: return core->cpsr.carry && !core->cpsr.zero;
        case COND_LS: return !core->cpsr.carry || core->cpsr.zero;
        case COND_GE: return core->cpsr.negative == core->cpsr.overflow;
        case COND_LT: return core->cpsr.negative != core->cpsr.overflow;
        case COND_GT: return !core->cpsr.zero && (core->cpsr.negative == core->cpsr.overflow);
        case COND_LE: return core->cpsr.zero || (core->cpsr.negative != core->cpsr.overflow);
        case COND_AL: return true;
        default:
            panic(CORE, "Unknown cond %u\n", cond);
    }
}