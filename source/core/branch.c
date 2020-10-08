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
core_branch(
    struct core *core,
    uint32_t op
) {
    int32_t offset;

    offset = sign_extend24(op & 0xFFFFFF) << 2;

    /*
    ** If the link bit (24) is set, the old PC is written in the link register.
    */
    if (bitfield_get(op, 24)) {
        core->r14 = core->r15 - 4;
        hs_logln(DEBUG, "lr <- 0x%08x", core->r14);
    }

    core->r15 += offset;
    hs_logln(DEBUG, "pc <- 0x%08x", core->r15);
}

/*
** Execute the Branch and Exchange instruction.
*/
void
core_branchxchg(
    struct core *core,
    uint32_t op
) {
    uint32_t rn;
    uint32_t addr;

    rn = op & 0xF;
    addr = core->registers[rn];

    core->r15 = addr & 0xFFFFFFFE;

    hs_logln(DEBUG, "pc <- 0x%08x", core->r15);

    core_cpsr_update_thumb(core, addr & 0b1);
}
