/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba.h"

/*
** Execute the Multiply (MUL) and Multiply Accumulate (MLA) instruction.
*/
void
core_arm_mul(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t rm;
    uint32_t rs;
    uint32_t rn;
    uint32_t rd;
    bool s;
    bool a;

    rm = bitfield_get_range(op, 0, 4);
    rs = bitfield_get_range(op, 8, 12);
    rn = bitfield_get_range(op, 12, 16);
    rd = bitfield_get_range(op, 16, 20);
    s = bitfield_get(op, 20);
    a = bitfield_get(op, 21);
    core = &gba->core;

    if (a) {
        core->registers[rd] = core->registers[rm] * core->registers[rs] + core->registers[rn];
    } else {
        core->registers[rd] = core->registers[rm] * core->registers[rs];
    }

    if (s) {
        core->cpsr.zero = !(core->registers[rd]);
        core->cpsr.negative = bitfield_get(core->registers[rd], 31);
    }


}