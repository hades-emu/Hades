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
** Execute the Multiply (MUL) and Multiply Accumulate (MLA) instruction.
*/
void
core_arm_mul(
    struct core *core,
    uint32_t op
) {
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

    if (a) {
        core->registers[rd] = core->registers[rm] * core->registers[rs] + core->registers[rn];
    } else {
        core->registers[rd] = core->registers[rm] * core->registers[rs];
    }

    if (s) {
        core->cpsr.zero = (core->registers[rd] == 0);
        core->cpsr.negative = ((core->registers[rd] & 0x80000000) != 0);
    }
}