/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "core.h"
#include "hades.h"

/*
** Execute the MRS instruction (transfer PSR contents to a register)
*/
void
core_arm_mrs(
    struct core *core,
    uint32_t op
) {
    uint32_t rd;

    rd = bitfield_get_range(op, 12, 16);
    if (bitfield_get(op, 22)) { // Source PSR = SPSR_<current_mode>
        unimplemented(CORE, "MRS with a source PSR different than the CPSR isn't implemented yet.");
    } else { // Source PSR = CPSR
        core->registers[rd] = core->cpsr.raw;
    }
}

/*
** Execute the MSR instruction (transfer register contents to PSR).
*/
void
core_arm_msr(
    struct core *core,
    uint32_t op
) {
    uint32_t rm;

    rm = bitfield_get_range(op, 0, 4);
    if (bitfield_get(op, 22)) { // Dest PSR = SPSR_<current_mode>
        unimplemented(CORE, "MSR with a dest PSR different than the CPSR isn't implemented yet.");
    } else { // Dest PSR = CPSR
        core->cpsr.raw = core->registers[rm];
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
    unimplemented(CORE, "The MSR instruction with flag bits is not implemented yet.");
}
