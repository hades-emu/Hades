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

/*
** An ARM core.
*/
struct core {
    struct {
        bool dump_asm;
    } debug;

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
            uint32_t r11;
            uint32_t r12;
            uint32_t r13;
            uint32_t r14;       // Link Register
            uint32_t r15;       // Program counter
        } __packed;
        uint32_t registers[16];
    };

    uint32_t cpsr;

    bool big_endian;
};

/*
** The user-friendly name of all registers
*/
static char const * const registers_name[] = {
    [0]     = "r0",
    [1]     = "r1",
    [2]     = "r2",
    [3]     = "r3",
    [4]     = "r4",
    [5]     = "r5",
    [6]     = "r6",
    [7]     = "r7",
    [8]     = "r8",
    [9]     = "r9",
    [10]    = "r10",
    [11]    = "fp",
    [12]    = "ip",
    [13]    = "sp",
    [14]    = "lr",
    [15]    = "pc",
};


/*
** The fifteen possible conditions
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
** The prefix used to describe which condition the following instruction uses.
*/
static char const * const cond_suffix[] = {
    [COND_EQ] = "EQ",
    [COND_NE] = "NE",
    [COND_CS] = "CS",
    [COND_CC] = "CC",
    [COND_MI] = "MI",
    [COND_PL] = "PL",
    [COND_VS] = "VS",
    [COND_VC] = "VC",
    [COND_HI] = "HI",
    [COND_LS] = "LS",
    [COND_GE] = "GE",
    [COND_LT] = "LT",
    [COND_GT] = "GT",
    [COND_LE] = "LE",
    [COND_AL] = "",
};

/*
** The offset, in bit, of each and every flag in the CPSR.
*/
enum cpsr_bits {
    CPSR_M0         = 0,
    CPSR_M1         = 1,
    CPSR_M2         = 2,
    CPSR_M3         = 3,
    CPSR_M4         = 4,
    CPSR_THUMB      = 5,
    CPSR_FIQ        = 6,
    CPSR_IRQ        = 7,
    CPSR_V          = 28,
    CPSR_C          = 29,
    CPSR_Z          = 30,
    CPSR_N          = 31,
};

/* branch.c */
void core_branch(struct core *core, uint32_t op);
void core_branchxchg(struct core *core, uint32_t op);

/* core.c */
void core_next_op(struct core *core);
uint32_t compute_shift(struct core *core, uint32_t encoded_shift, uint32_t value, bool update_carry);
void core_cpsr_update_thumb(struct core *core, bool thumb);
void core_cpsr_update_carry(struct core *core, bool carry);
void core_cpsr_update_zn(struct core *core, uint32_t val);
void core_cpsr_update_overflow(struct core *core, bool overflow);

/* data.c */
void core_data_processing(struct core *core, uint32_t op);

/* mem.c */
uint8_t core_mem_read8(struct core const *core, uint32_t addr);
void core_mem_write8(struct core *core, uint32_t addr, uint8_t val);
uint16_t core_mem_read16(struct core const *core, uint32_t addr);
void core_mem_write16(struct core *core, uint32_t addr, uint16_t val);
uint32_t core_mem_read32(struct core const *core, uint32_t addr);
void core_mem_write32(struct core *core, uint32_t addr, uint32_t val);

/* sdt.c */
void core_sdt(struct core *core, uint32_t op);

#endif /* !CORE_H */
