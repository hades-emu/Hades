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

    rd = bitfield_get_range(op, 12, 16);

    if (bitfield_get(op, 22)) { // Source PSR = SPSR_<current_mode>
        unimplemented(HS_CORE, "MRS with a source PSR different than the CPSR isn't implemented yet.");
    } else { // Source PSR = CPSR
        gba->core.registers[rd] = gba->core.cpsr.raw;
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
        unimplemented(HS_CORE, "MSR with a dest PSR different than the CPSR isn't implemented yet.");
    } else { // Dest PSR = CPSR
        uint32_t new_cpsr;

        new_cpsr = core->registers[rm];

        core_switch_mode(core, new_cpsr & 0x1F);

        core->cpsr.raw = new_cpsr;
    }
}

/*
** Execute the MSR instruction (transfer register contents or immediate value to PSR flag bits only)
*/
void
core_arm_msrf(
    struct core *core,
    uint32_t op
) {
    unimplemented(HS_CORE, "The MSR instruction with flag bits is not implemented yet.");
}
