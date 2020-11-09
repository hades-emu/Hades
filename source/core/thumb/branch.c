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
** Implement the unconditional branch instruction.
*/
void
core_thumb_branch(
    struct core *core,
    uint16_t op
) {
    int32_t offset;

    offset = sign_extend12(bitfield_get_range(op, 0, 11) << 1);

    core->pc += offset;
    core_reload_pipeline(core);
}

/*
** Implement the two sides of the BL instruction.
*/
void
core_thumb_branchlink(
    struct core *core,
    uint16_t op
) {
    uint32_t offset;
    bool h;

    h = bitfield_get(op, 11);
    offset = bitfield_get_range(op, 0, 11);

    if (!h) {
        core->lr = core->pc + (sign_extend11(offset) << 12);
    } else {
        uint32_t lr;

        lr = core->lr + (offset << 1);

        core->lr = (core->pc - 2) | 1;
        core->pc = lr;
        core_reload_pipeline(core);
    }
}

/*
** Execute the Conditional Branch instructions (BEQ, BNE, etc.).
*/
void
core_thumb_branch_cond(
    struct core *core,
    uint16_t op
) {
    bool can_exec;
    uint32_t label;

    label = bitfield_get_range(op, 0, 8) << 1;
    can_exec = core_compute_cond(core, bitfield_get_range(op, 8, 12));

    if (can_exec) {
        core->pc += label;
        core_reload_pipeline(core);
    }
}

/*
** Implement the Branch Exchange instruction.
*/
void
core_thumb_branchxchg(
    struct core *core,
    uint16_t op
) {
    uint32_t addr;
    uint16_t rs;
    bool h;

    h = bitfield_get(op, 6);
    rs = bitfield_get_range(op, 3, 6) + h * 8;

    hs_assert(!bitfield_get(op, 7));

    addr = core->registers[rs];

    /*
    ** Mask out the last bit which used to indicate if Thumb mode must be entered.
    */
    core->pc = addr & 0xFFFFFFFE;
    core->cpsr.thumb = addr & 0b1;
    core_reload_pipeline(core);
}
