/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

/*
** References:
**   * ARM7TDMI Data Sheet
**      https://www.dwedit.org/files/ARM7TDMI.pdf
*/

#ifndef CORE_H
# define CORE_H

# include <stdbool.h>
# include <stdint.h>
# include "hades.h"
# include "memory.h"

struct gba;

struct psr {
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
    };
} __packed;

struct core {
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
            uint32_t fp;       // r11
            uint32_t ip;       // r12
            uint32_t sp;       // r13
            uint32_t lr;       // r14
            uint32_t pc;       // r15
        } __packed;
        uint32_t registers[16];
    };

    union {
        struct {
            uint32_t r8_sys;
            uint32_t r9_sys;
            uint32_t r10_sys;
            uint32_t r11_sys;
            uint32_t r12_sys;
            uint32_t r13_sys;
            uint32_t r14_sys;
            struct psr spsr_sys;

            uint32_t r8_fiq;
            uint32_t r9_fiq;
            uint32_t r10_fiq;
            uint32_t r11_fiq;
            uint32_t r12_fiq;
            uint32_t r13_fiq;
            uint32_t r14_fiq;
            struct psr spsr_fiq;

            uint32_t r13_svc;
            uint32_t r14_svc;
            struct psr spsr_svc;

            uint32_t r13_abt;
            uint32_t r14_abt;
            struct psr spsr_abt;

            uint32_t r13_irq;
            uint32_t r14_irq;
            struct psr spsr_irq;

            uint32_t r13_und;
            uint32_t r14_und;
            struct psr spsr_und;
        } __packed;
        uint32_t bank_registers[28];
    };

    uint32_t prefetch[2];              // The next instruction to be executed
    enum access_type prefetch_access_type;

    struct psr cpsr;

    uint32_t halt;                  // 0=Run, 1=Halt, 2=Stop

    uint64_t cycles;                // Amount of cycles spent by the CPU since initialization
};

/*
** The fifteen possible conditions that prefixes an instruction.
*/
enum arm_conds {
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
** An enumeration of all the different modes.
*/
enum arm_modes {
    MODE_USR            = 0b10000,
    MODE_FIQ            = 0b10001,
    MODE_IRQ            = 0b10010,
    MODE_SVC            = 0b10011,
    MODE_ABT            = 0b10111,
    MODE_UND            = 0b11011,
    MODE_SYS            = 0b11111,
};

/*
** An enumartion of all the interrupt vectors the ARM7TDMI supports.
*/
enum arm_vectors {
    VEC_RESET           = 0x00, // Reset
    VEC_UND             = 0x04, // Undefined Instruction
    VEC_SVC             = 0x08, // Supervisor Call / Software Interrupt
    VEC_PABT            = 0x0c, // Prefetch Abort
    VEC_DABT            = 0x10, // Data Abort
    VEC_ADDR26          = 0x14, // Address exceeds 26 bits (legacy)
    VEC_IRQ             = 0x18, // Normal Interrupt
    VEC_FIQ             = 0x1c, // Fast Interrupt
};

/*
** An enumeration of all
*/
enum arm_irq {
    IRQ_VBLANK          = 0x0,
    IRQ_HBLANK          = 0x1,
    IRQ_VCOUNTER        = 0x2,
    IRQ_TIMER0          = 0x3,
    IRQ_TIMER1          = 0x4,
    IRQ_TIMER2          = 0x5,
    IRQ_TIMER3          = 0x6,
    IRQ_SERIAL          = 0x7,
    IRQ_DMA0            = 0x8,
    IRQ_DMA1            = 0x9,
    IRQ_DMA2            = 0xA,
    IRQ_DMA3            = 0xB,
    IRQ_KEYPAD          = 0xC,
    IRQ_GAMEPAK         = 0xD,
};

/*
** The user-friendly name of all modes.
*/
static char const * const arm_modes_name[] = {
    [MODE_USR]          = "usr",
    [MODE_FIQ]          = "fiq",
    [MODE_IRQ]          = "irq",
    [MODE_SVC]          = "svc",
    [MODE_ABT]          = "abt",
    [MODE_UND]          = "und",
    [MODE_SYS]          = "sys"
};

/* core/core.c */
void core_init(struct gba *gba);
void core_run(struct gba *gba);
void core_next(struct gba *gba);
void core_idle(struct gba *gba);
void core_idle_for(struct gba *gba, uint32_t cycles);
void core_reload_pipeline(struct gba *gba);
struct psr core_spsr_get(struct core const *core, enum arm_modes mode);
void core_spsr_set(struct core *core, enum arm_modes mode, struct psr psr);
void core_switch_mode(struct core *core, enum arm_modes mode);
uint32_t core_compute_shift(struct core *core, uint32_t encoded_shift, uint32_t value, bool *update_carry);
bool core_compute_cond(struct core *core, uint32_t cond);
void core_trigger_irq(struct gba *gba, enum arm_irq irq);
void core_scan_irq(struct gba *gba);

/* core/interrupt.c */
void core_interrupt(struct gba *gba, enum arm_vectors vector, enum arm_modes mode);

#endif /* !CORE_H */