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
#include "gba/core/arm.h"

/*
** Implement the unconditional branch instruction.
*/
void
core_thumb_branch(
    struct gba *gba,
    uint16_t op
) {
    int32_t offset;

    offset = sign_extend12(bitfield_get_range(op, 0, 11) << 1);

    gba->core.pc += offset;
    core_reload_pipeline(gba);
}

/*
** Implement the two sides of the BL instruction.
*/
void
core_thumb_branch_link(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t offset;
    bool h;

    h = bitfield_get(op, 11);
    offset = bitfield_get_range(op, 0, 11);
    core = &gba->core;

    if (!h) {
        core->lr = core->pc + (sign_extend11(offset) << 12);
        core->pc += 2;
        core->prefetch_access_type = SEQUENTIAL;
    } else {
        uint32_t lr;

        lr = core->lr + (offset << 1);

        core->lr = (core->pc - 2) | 1;
        core->pc = lr;
        core_reload_pipeline(gba);
    }
}

/*
** Execute the Conditional Branch instructions (BEQ, BNE, etc.).
*/
void
core_thumb_branch_cond(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    size_t idx;
    int32_t label;

    core = &gba->core;
    label = ((int32_t)(int8_t)bitfield_get_range(op, 0, 8)) << 1;
    idx = (bitfield_get_range(core->cpsr.raw, 28, 32) << 4) | bitfield_get_range(op, 8, 12);

    if (cond_lut[idx]) {
        core->pc += label;
        core_reload_pipeline(gba);
    } else {
        core->pc += 2;
        core->prefetch_access_type = SEQUENTIAL;
    }
}

/*
** Implement the Branch Exchange (BX) instruction.
*/
void
core_thumb_branch_xchg(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t addr;
    uint16_t rs;
    bool h;

    h = bitfield_get(op, 6);
    rs = bitfield_get_range(op, 3, 6) + h * 8;

    hs_assert(!bitfield_get(op, 7));

    core = &gba->core;
    addr = core->registers[rs];

    /*
    ** Mask out the last bit which used to indicate if Thumb mode must be entered.
    */
    core->pc = addr & 0xFFFFFFFE;
    core->cpsr.thumb = addr & 0b1;
    core_reload_pipeline(gba);
}
