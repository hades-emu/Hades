/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba/gba.h"

/*
** Execute the Branch and Branch With Link instructions.
*/
void
core_arm_branch(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    int32_t offset;

    core = &gba->core;
    offset = (int32_t)((uint32_t)sign_extend24(op & 0xFFFFFF) << 2u);

    /*
    ** If the link bit (24) is set, the old PC is written in the link register.
    */
    if (bitfield_get(op, 24)) {
        core->lr = core->pc - 4;
    }

    /*
    ** I believe adding `offset` (signed) to `core->pc` (unsigned) is safe.
    ** I'll be promoted to an unsigned value, sure, but that promotion is defined.
    ** As per C11's 6.3.1.3, when casting the negative value to unsigned the compiler
    ** mathematically adds UINT32_MAX + 1 to the value. That preserves additions
    ** and our resulting value is the correct one.
    */
    core->pc += offset;
    core_reload_pipeline(gba);
}

/*
** Execute the Branch and Exchange instruction.
*/
void
core_arm_branch_xchg(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t rn;
    uint32_t addr;

    core = &gba->core;
    rn = op & 0xF;
    addr = core->registers[rn];

    /*
    ** Mask out the last bit which used to indicate if Thumb mode must be entered.
    */
    core->pc = addr & 0xFFFFFFFE;
    core->cpsr.thumb = addr & 0b1;
    core_reload_pipeline(gba);
}
