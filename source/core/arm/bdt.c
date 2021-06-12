/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba.h"

void
core_arm_bdt(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t i;
    uint32_t rn;
    uint32_t base;
    uint32_t base_new;
    int32_t count;
    bool reload_pipeline;
    bool first;
    bool load;
    bool pre;
    bool wb;

    core = &gba->core;
    reload_pipeline = false;
    rn = bitfield_get_range(op, 16, 20);
    load = bitfield_get(op, 20);
    pre = bitfield_get(op, 24);
    wb = bitfield_get(op, 21);

    /*
    ** Count how many registers we are going to transfer
    */

    i = 0;
    count = 0;
    while (i < 16) {
        count += (bitfield_get(op, i));
        ++i;
    }

    base = core->registers[rn];

    /*
    ** Pre-calculate the end address and go incrementally from
    ** there.
    **
    ** This part is inspired by Fleroviux's NanoBoyAdvance implementation.
    ** Thank you for your amazing work!
    */
    if (bitfield_get(op, 23)) { // Up
        base_new = base + count * 4;
    } else { // Down
        pre = !pre;
        base -= count * 4;
        base_new = base;
    }

    i = 0;
    first = true;
    while (i < 16) {
        if (bitfield_get(op, i)) {
            base += pre ? 4 : 0; // Pre-increment

            if (load) {
                core->registers[i] = mem_read32(gba, base);
                printf("Loading [%08x] %08x to r%u\n", base, core->registers[i], i);
                reload_pipeline |= (i == 15);
            } else {
                mem_write32(gba, base, core->registers[i] + (i == 15) * 4);
                printf("Storing r%u %08x to [%08x]\n", i, core->registers[i], base);
            }

            base += pre ? 0 : 4; // Post-increment

            if (first && wb) { // Write back
                core->registers[rn] = base_new;
                first = false;
            }
        }
        ++i;
    }

    if (reload_pipeline) {
        core_reload_pipeline(gba);
    }
}