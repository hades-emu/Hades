/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba/gba.h"

/*
** Implement the Logical Shift Left instructions.
*/
void
core_thumb_lsl(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t rs;
    uint32_t shift;
    uint32_t value;

    rd = bitfield_get_range(op, 0, 3);
    rs = bitfield_get_range(op, 3, 6);
    shift = bitfield_get_range(op, 6, 11);

    core = &gba->core;
    value = core->registers[rs];

    /* LSL (Logical Shift Left) */

    if (shift > 0) {
        value <<= shift - 1;
        core->cpsr.carry = value >> 31;
        value <<= 1;
    }

    core->cpsr.zero = !value;
    core->cpsr.negative = bitfield_get(value, 31);

    core->registers[rd] = value;

    core->pc += 2;
    core->prefetch_access_type = SEQUENTIAL;
}

/*
** Implement the Logical Shift Right instructions.
*/
void
core_thumb_lsr(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t rs;
    uint32_t shift;
    uint32_t value;

    rd = bitfield_get_range(op, 0, 3);
    rs = bitfield_get_range(op, 3, 6);
    shift = bitfield_get_range(op, 6, 11);

    core = &gba->core;
    value = core->registers[rs];

    /* LSR (Logical Shift Right) */

    if (shift == 0) {
        shift = 32;
    }

    value >>= shift - 1;
    core->cpsr.carry = value & 0b1;
    value >>= 1;

    core->cpsr.zero = !value;
    core->cpsr.negative = bitfield_get(value, 31);

    core->registers[rd] = value;

    core->pc += 2;
    core->prefetch_access_type = SEQUENTIAL;
}

/*
** Implement the Arithmetic Shift Right instructions.
*/
void
core_thumb_asr(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t rs;
    uint32_t shift;
    uint32_t value;

    rd = bitfield_get_range(op, 0, 3);
    rs = bitfield_get_range(op, 3, 6);
    shift = bitfield_get_range(op, 6, 11);

    core = &gba->core;
    value = core->registers[rs];

    /* ASR (Arithmetic Shift Right) */

    if (shift == 0) {
        shift = 32;
    }

    value = (int32_t)value >> (shift - 1);
    core->cpsr.carry = value & 0b1;
    value = (int32_t)value >> 1;

    core->cpsr.zero = !value;
    core->cpsr.negative = bitfield_get(value, 31);

    core->registers[rd] = value;

    core->pc += 2;
    core->prefetch_access_type = SEQUENTIAL;
}
