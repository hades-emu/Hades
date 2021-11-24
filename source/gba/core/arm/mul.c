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

static
void
core_arm_mul_idle_signed(
    struct gba *gba,
    uint32_t rs
) {
    uint32_t x;
    uint32_t mask;
    uint32_t cycles;

    cycles = 1;
    mask = 0xFFFFFF00;
    for (x = 0; x < 4; ++x) {

        rs &= mask;

        if (rs == 0 || rs == mask) {
            break;
        }

        mask <<= 8u;
        cycles += 1;
    }
    core_idle_for(gba, cycles);
}

static
void
core_arm_mul_idle_unsigned(
    struct gba *gba,
    uint32_t rs
) {
    uint32_t x;
    uint32_t mask;
    uint32_t cycles;

    cycles = 1;
    mask = 0xFFFFFF00;
    for (x = 0; x < 4; ++x) {

        rs &= mask;

        if (rs == 0) {
            break;
        }

        mask <<= 8u;
        cycles += 1;
    }
    core_idle_for(gba, cycles);
}

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

    core = &gba->core;

    rm = bitfield_get_range(op, 0, 4);
    rs = bitfield_get_range(op, 8, 12);
    rn = bitfield_get_range(op, 12, 16);
    rd = bitfield_get_range(op, 16, 20);
    s = bitfield_get(op, 20);
    a = bitfield_get(op, 21);

    // This must be done first in case Rs is also Rd.
    core_arm_mul_idle_signed(gba, core->registers[rs]);

    if (a) {
        core->registers[rd] = core->registers[rm] * core->registers[rs] + core->registers[rn];
        core_idle(gba);
    } else {
        core->registers[rd] = core->registers[rm] * core->registers[rs];
    }

    if (s) {
        core->cpsr.zero = !(core->registers[rd]);
        core->cpsr.negative = bitfield_get(core->registers[rd], 31);
    }

    core->pc += 4;
    core->prefetch_access_type = NON_SEQUENTIAL;
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

    core = &gba->core;
    core->prefetch_access_type = SEQUENTIAL;

    rm = bitfield_get_range(op, 0, 4);
    rs = bitfield_get_range(op, 8, 12);
    rd_lo = bitfield_get_range(op, 12, 16);
    rd_hi = bitfield_get_range(op, 16, 20);
    s = bitfield_get(op, 20);
    a = bitfield_get(op, 21);
    u = bitfield_get(op, 22);

    core_idle(gba);

    switch (((uint32_t)u << 1) | a) {
        // UMULL
        case 0b00: {
            core_arm_mul_idle_unsigned(gba, core->registers[rs]);
            ures = (uint64_t)core->registers[rm] * (uint64_t)core->registers[rs];
            break;
        };
        // UMLAL
        case 0b01: {
            core_arm_mul_idle_unsigned(gba, core->registers[rs]);
            core_idle(gba);
            ures = (uint64_t)core->registers[rd_lo] | ((uint64_t)core->registers[rd_hi] << 32);
            ures += (uint64_t)core->registers[rm] * (uint64_t)core->registers[rs];
            break;
        };
        // SMULL
        case 0b10: {
            core_arm_mul_idle_signed(gba, core->registers[rs]);
            ires = (int64_t)(int32_t)core->registers[rm] * (int64_t)(int32_t)core->registers[rs];
            ures = ires;
            break;
        };
        // SMLAL
        default: {
            core_arm_mul_idle_signed(gba, core->registers[rs]);
            core_idle(gba);
            ures = (uint64_t)core->registers[rd_lo] | ((uint64_t)core->registers[rd_hi] << 32);
            ires = ures;
            ires += (int64_t)(int32_t)core->registers[rm] * (int64_t)(int32_t)core->registers[rs];
            ures = ires;
            break;
        };
    }

    core->registers[rd_lo] = ures & 0xFFFFFFFF;
    core->registers[rd_hi] = (ures >> 32) & 0xFFFFFFFF;

    if (s) {
        core->cpsr.zero = !(core->registers[rd_hi]) && !(core->registers[rd_lo]);
        core->cpsr.negative = bitfield_get(core->registers[rd_hi], 31);
    }

    core->pc += 4;
    core->prefetch_access_type = NON_SEQUENTIAL;
}