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
** Execute the Single Data Swap instruction.
*/
void
core_arm_swp(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t tmp;
    uint32_t rm;
    uint32_t rn;
    uint32_t rd;

    core = &gba->core;

    rm = bitfield_get_range(op, 0, 4);
    rd = bitfield_get_range(op, 12, 16);
    rn = bitfield_get_range(op, 16, 20);

    if (bitfield_get(op, 22)) { // Swap byte quantity
        tmp = mem_read8(gba, core->registers[rn], NON_SEQUENTIAL);
        mem_write8(gba, core->registers[rn], core->registers[rm], NON_SEQUENTIAL);
        core->registers[rd] = tmp;
    } else { // Swap word quantity
        tmp = mem_read32_ror(gba, core->registers[rn], NON_SEQUENTIAL);
        mem_write32(gba, core->registers[rn], core->registers[rm], NON_SEQUENTIAL);
        core->registers[rd] = tmp;
    }

    core_idle(gba);

    if (rd == 15) {
        core_reload_pipeline(gba);
    } else {
        core->pc += 4;
        core->prefetch_access_type = NON_SEQUENTIAL;
    }
}
