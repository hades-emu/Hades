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

/*
** Execute the {Unsigned,Signed} Multiply Long (MULL) and Unsigned Multiply Accumulate (MLAL) instruction.
*/
void
core_arm_mull(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t rm;
    uint32_t rs;
    uint32_t rd_hi;
    uint32_t rd_lo;
    uint64_t ures;
    int64_t ires;
    bool s;
    bool a;
    bool u;

    rm = bitfield_get_range(op, 0, 4);
    rs = bitfield_get_range(op, 8, 12);
    rd_lo = bitfield_get_range(op, 12, 16);
    rd_hi = bitfield_get_range(op, 16, 20);
    s = bitfield_get(op, 20);
    a = bitfield_get(op, 21);
    u = bitfield_get(op, 22);
    core = &gba->core;

    switch ((u << 1) | a) {
        // UMULL
        case 0b00:
            ures = (uint64_t)core->registers[rm] * (uint64_t)core->registers[rs];
            break;
        // UMLAL
        case 0b01:
            ures = (uint64_t)core->registers[rd_lo] | ((uint64_t)core->registers[rd_hi] << 32);
            ures += (uint64_t)core->registers[rm] * (uint64_t)core->registers[rs];
            break;
        // SMULL
        case 0b10:
            ires = (int64_t)(int32_t)core->registers[rm] * (int64_t)(int32_t)core->registers[rs];
            ures = ires;
            break;
        // SMLAL
        case 0b11:
            ures = (uint64_t)core->registers[rd_lo] | ((uint64_t)core->registers[rd_hi] << 32);
            ires = ures;
            ires += (int64_t)(int32_t)core->registers[rm] * (int64_t)(int32_t)core->registers[rs];
            ures = ires;
            break;
    }

    core->registers[rd_lo] = ures & 0xFFFFFFFF;
    core->registers[rd_hi] = (ures >> 32) & 0xFFFFFFFF;

    if (s) {
        core->cpsr.zero = !(core->registers[rd_hi]) && !(core->registers[rd_lo]);
        core->cpsr.negative = bitfield_get(core->registers[rd_hi], 31);
    }
}