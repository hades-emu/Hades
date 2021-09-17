/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba/gba.h"

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
        core->registers[rd] = core_spsr_get(core, core->cpsr.mode).raw;
    } else { // Source PSR = CPSR
        core->registers[rd] = gba->core.cpsr.raw;
    }

    core->pc += 4;
    core->prefetch_access_type = SEQUENTIAL;
}

/*
** Execute the MSRF instruction (transfer register contents or immediate value to PSR flag bits only)
*/
void
core_arm_msr(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t val;
    uint32_t mask;

    core = &gba->core;
    if (bitfield_get(op, 25)) { // Immediate
        uint32_t shift;
        uint32_t imm;

        imm = bitfield_get_range(op, 0, 8);
        shift = bitfield_get_range(op, 8, 12) * 2;

        val = ror32(imm, shift);
    } else { // Reg
        val = core->registers[bitfield_get_range(op, 0, 4)];
    }

    /* Build the mask */

    mask = 0;
    mask |= (0x000000FF) * bitfield_get(op, 16);
    mask |= (0x0000FF00) * bitfield_get(op, 17);
    mask |= (0x00FF0000) * bitfield_get(op, 18);
    mask |= (0xFF000000) * bitfield_get(op, 19);

    if (bitfield_get(op, 22)) { // Set SPSR_<mode>
        struct psr spsr;

        spsr = core_spsr_get(core, core->cpsr.mode);
        spsr.raw = (spsr.raw & ~mask) | (val & mask);
        core_spsr_set(core, core->cpsr.mode, spsr);
    } else { // Set CPSR
        struct psr new_cpsr;

        // In user mode, only the condition flags can be set, not the control flags.
        if  (core->cpsr.mode == MODE_USR) {
            mask &= 0xFF000000;
        }

        new_cpsr = core->cpsr;
        new_cpsr.raw = (new_cpsr.raw & ~mask) | (val & mask);
        if (new_cpsr.mode != core->cpsr.mode) {
            core_switch_mode(core, new_cpsr.mode);
        }
        core->cpsr = new_cpsr;
    }

    core->pc += 4;
    core->prefetch_access_type = SEQUENTIAL;
}
