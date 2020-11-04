/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "core.h"

/*
** Execute the Branch and Branch With Link instructions.
*/
void
core_arm_branch(
    struct core *core,
    uint32_t op
) {
    int32_t offset;

    offset = sign_extend24(op & 0xFFFFFF) << 2u;

    /*
    ** If the link bit (24) is set, the old PC is written in the link register.
    */
    if (bitfield_get(op, 24)) {
        core->r14 = core->r15 - 4;
    }

    /*
    ** I believe adding `offset` (signed) to `core->r15` (unsigned) is safe.
    ** I'll be promoted to an unsigned value, sure, but that promotion is defined.
    ** As per C11's 6.3.1.3, when casting the negative value to unsigned the compiler
    ** mathematically adds UINT32_MAX + 1 to the value. That preserves additions
    ** and our resulting value is the correct one.
    */
    core->r15 += offset;
    core_reload_pipeline(core);
}

/*
** Execute the Branch and Exchange instruction.
*/
void
core_arm_branchxchg(
    struct core *core,
    uint32_t op
) {
    uint32_t rn;
    uint32_t addr;

    rn = op & 0xF;
    addr = core->registers[rn];

    /*
    ** Mask out the last bit which used to indicate if Thumb mode must be entered.
    */
    core->r15 = addr & 0xFFFFFFFE;
    core->cpsr.thumb = addr & 0b1;
    core_reload_pipeline(core);
}
