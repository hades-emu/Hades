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
** Execute the MRS instruction (PSR to general-purpose register)
*/
void
core_arm_mrs(
    struct gba *gba,
    uint32_t op
) {
    uint32_t rd;
    struct core *core;

    core = &gba->core;
    rd = bitfield_get_range(op, 12, 16);

    if (bitfield_get(op, 22)) { // Source PSR = SPSR_<current_mode>
        switch (core->cpsr.mode) {
            case MODE_USER:
                panic(HS_CORE, "mrs: a SPSR for user mode was requested but it doesn't exist.");
                break;
            case MODE_FIQ:
                core->registers[rd] = core->spsr_fiq;
                break;
            case MODE_IRQ:
                core->registers[rd] = core->spsr_irq;
                break;
            case MODE_SUPERVISOR:
                core->registers[rd] = core->spsr_svc;
                break;
            case MODE_ABORT:
                core->registers[rd] = core->spsr_abt;
                break;
            case MODE_UNDEFINED:
                core->registers[rd] = core->spsr_und;
                break;
            case MODE_SYSTEM:
                core->registers[rd] = core->spsr_sys;
                break;
        }
    } else { // Source PSR = CPSR
        core->registers[rd] = gba->core.cpsr.raw;
    }
}

/*
** Execute the MSR instruction (general-purpose register to PSR)
*/
void
core_arm_msr(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t rm;

    core = &gba->core;
    rm = bitfield_get_range(op, 0, 4);

    if (bitfield_get(op, 22)) { // Dest PSR = SPSR_<current_mode>
        switch (core->cpsr.mode) {
            case MODE_USER:
                panic(HS_CORE, "mrs: a SPSR for user mode was requested but it doesn't exist.");
                break;
            case MODE_FIQ:
                core->spsr_fiq = core->registers[rm];
                break;
            case MODE_IRQ:
                core->spsr_irq = core->registers[rm];
                break;
            case MODE_SUPERVISOR:
                core->spsr_svc = core->registers[rm];
                break;
            case MODE_ABORT:
                core->spsr_abt = core->registers[rm];
                break;
            case MODE_UNDEFINED:
                core->spsr_und = core->registers[rm];
                break;
            case MODE_SYSTEM:
                core->spsr_sys = core->registers[rm];
                break;
        }
    } else { // Dest PSR = CPSR
        uint32_t new_cpsr;

        new_cpsr = core->registers[rm];

        core_switch_mode(core, new_cpsr & 0x1F);

        core->cpsr.raw = new_cpsr;
    }
}

/*
** Execute the MSRF instruction (transfer register contents or immediate value to PSR flag bits only)
*/
void
core_arm_msrf(
    struct core *core,
    uint32_t op
) {
    unimplemented(HS_CORE, "The MSR instruction with flag bits is not implemented yet.");
}
