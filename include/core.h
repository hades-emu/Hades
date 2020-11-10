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

#ifndef CORE_H
# define CORE_H

# include <stdint.h>
# include <stdlib.h>
# include "hades.h"

struct debugger;

/*
** An ARM core.
*/
struct core {
    struct debugger *debugger;      // The debugger this core is linked with.

    uint8_t *memory;
    size_t memory_size;

    union {
        struct {
            uint32_t r0;
            uint32_t r1;
            uint32_t r2;
            uint32_t r3;
            uint32_t r4;
            uint32_t r5;
            uint32_t r6;
            uint32_t r7;
            uint32_t r8;
            uint32_t r9;
            uint32_t r10;
            uint32_t fp;       // FP
            uint32_t ip;       // IP
            uint32_t sp;       // SP
            uint32_t lr;       // LR
            uint32_t pc;       // PC
        } __packed;
        uint32_t registers[16];
    };

    uint32_t prefetch;              // The next instruction to be executed
    bool force_pipeline_reload;     // Forces a reload of the 3-stage pipeline

    union {
        struct {
#ifdef __BIG_ENDIAN__
            uint32_t negative: 1;
            uint32_t zero: 1;
            uint32_t carry: 1;
            uint32_t overflow: 1;
            uint32_t : 20;
            uint32_t irq_disable: 1;
            uint32_t fiq_disable: 1;
            uint32_t state: 1;
            uint32_t mode: 5;
#else
            uint32_t mode: 5;
            uint32_t thumb: 1;
            uint32_t fiq_disable: 1;
            uint32_t irq_disable: 1;
            uint32_t : 20;
            uint32_t overflow: 1;
            uint32_t carry: 1;
            uint32_t zero: 1;
            uint32_t negative: 1;
#endif
        };
        uint32_t raw;
    } cpsr __packed;

    uint8_t big_endian;
};

/*
** The fifteen possible conditions that prefixes an instruction.
*/
enum opcode_cond {
    COND_EQ = 0b0000,   // Equal
    COND_NE = 0b0001,   // Not Equal
    COND_CS = 0b0010,   // Unsigned higher or same
    COND_CC = 0b0011,   // Unsigned lower
    COND_MI = 0b0100,   // Negative
    COND_PL = 0b0101,   // Positive or zero
    COND_VS = 0b0110,   // Overflow
    COND_VC = 0b0111,   // No overflow
    COND_HI = 0b1000,   // Unsigned higher
    COND_LS = 0b1001,   // Unsigned lower or same
    COND_GE = 0b1010,   // Greater or equal
    COND_LT = 0b1011,   // Less than
    COND_GT = 0b1100,   // Greather than
    COND_LE = 0b1101,   // Less than or equal
    COND_AL = 0b1110,   // Always
};

/*
** An enumeration of all the modes the processor can be in.
*/
enum core_modes {
    MODE_USER            = 0b10000,
    MODE_FIQ             = 0b10001,
    MODE_IRQ             = 0b10010,
    MODE_SUPERVISOR      = 0b10011,
    MODE_ABORT           = 0b10111,
    MODE_UNDEFINED       = 0b11011,
    MODE_SYSTEM          = 0b11111,
};

/* core/arm/alu.c */
void core_arm_alu(struct core *core, uint32_t op);

/* core/arm/branch.c */
void core_arm_branch(struct core *core, uint32_t op);
void core_arm_branchxchg(struct core *core, uint32_t op);

/* core/arm/mul.c */
void core_arm_mul(struct core *core, uint32_t op);

/* core/arm/psr.c */
void core_arm_mrs(struct core *core, uint32_t op);
void core_arm_msr(struct core *core, uint32_t op);
void core_arm_msrf(struct core *core, uint32_t op);

/* core/arm/sdt.c */
void core_arm_sdt(struct core *core, uint32_t op);

/* core/thumb/alu.c */
void core_thumb_add(struct core *core, uint16_t op);
void core_thumb_sub(struct core *core, uint16_t op);
void core_thumb_add_from_sp(struct core *core, uint16_t op);
void core_thumb_add_from_pc(struct core *core, uint16_t op);
void core_thumb_alu(struct core *core, uint16_t op);
void core_thumb_add_reg(struct core *core, uint16_t op);
void core_thumb_cmp_reg(struct core *core, uint16_t op);
void core_thumb_mov_reg(struct core *core, uint16_t op);
void core_thumb_mov_imm(struct core *core, uint16_t op);
void core_thumb_cmp_imm(struct core *core, uint16_t op);
void core_thumb_add_imm(struct core *core, uint16_t op);
void core_thumb_sub_imm(struct core *core, uint16_t op);
void core_thumb_add_sp(struct core *core, uint16_t op);

/* core/thumb/branch.c */
void core_thumb_branch(struct core *core, uint16_t op);
void core_thumb_branchlink(struct core *core, uint16_t op);
void core_thumb_branch_cond(struct core *core, uint16_t op);
void core_thumb_branchxchg(struct core *core, uint16_t op);

/* core/thumb/loadstore.c */
void core_thumb_push(struct core *core, uint16_t op);
void core_thumb_pop(struct core *core, uint16_t op);
void core_thumb_sdt_imm(struct core *core, uint16_t op);
void core_thumb_sdt_reg(struct core *core, uint16_t op);
void core_thumb_sdt_halfword(struct core *core, uint16_t op);
void core_thumb_sdt_sign_halfword(struct core *core, uint16_t op);
void core_thumb_ldr_pc(struct core *core, uint16_t op);
void core_thumb_sdt_sp(struct core *core, uint16_t op);

/* core/thumb/logical.c */
void core_thumb_lsl(struct core *core, uint16_t op);
void core_thumb_lsr(struct core *core, uint16_t op);
void core_thumb_asr(struct core *core, uint16_t op);

/* core/bus.c */
uint8_t core_bus_read8(struct core const *core, uint32_t addr);
void core_bus_write8(struct core *core, uint32_t addr, uint8_t val);
uint32_t core_bus_read16(struct core const *core, uint32_t addr);
void core_bus_write16(struct core *core, uint32_t addr, uint16_t val);
uint32_t core_bus_read32(struct core const *core, uint32_t addr);
void core_bus_write32(struct core *core, uint32_t addr, uint32_t val);

/* core/core.c */
void core_init(struct core *core, uint8_t *mem, size_t mem_size);
void core_run(struct core *core);
void core_reset(struct core *core);
void core_step(struct core *core);
void core_reload_pipeline(struct core *core);
uint32_t core_compute_shift(struct core *core, uint32_t encoded_shift, uint32_t value, bool update_carry);
bool core_compute_cond(struct core *core, uint32_t cond);

#endif /* !CORE_H */
