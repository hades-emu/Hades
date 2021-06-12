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
    enum arm_modes mode_old;
    bool mode_switch;
    bool pc_in_rlist;
    bool first;
    bool load;
    bool pre;
    bool s;
    bool wb;

    core = &gba->core;
    rn = bitfield_get_range(op, 16, 20);
    load = bitfield_get(op, 20);
    pre = bitfield_get(op, 24);
    wb = bitfield_get(op, 21);
    s = bitfield_get(op, 22);

    /*
    ** Count how many registers we are going to transfer
    */

    i = 0;
    count = 0;
    while (i < 16) {
        count += (bitfield_get(op, i));
        ++i;
    }

    /*
    ** Edge case: if rlist is empty, transfer the pc but
    ** increment the base as if all registers were transfered.
    */
    if (count == 0) {
        op |= (1 << 15);
        count = 16;
    }

    base = core->registers[rn];
    pc_in_rlist = bitfield_get(op, 15);

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

    /*
    ** User bank transfer:
    **
    ** The registers transferred are taken from the User bank rather
    ** than the bank corresponding to the current mode
    */
    if (s && (!pc_in_rlist || !load)) {
        mode_old = core->cpsr.mode;
        core_switch_mode(core, MODE_USR);
        mode_switch = true;
    } else {
        mode_switch = false;
    }

    i = 0;
    first = true;
    while (i < 16) {
        if (bitfield_get(op, i)) {
            base += pre ? 4 : 0; // Pre-increment

            if (load) {
                core->registers[i] = mem_read32(gba, base);
            } else {
                mem_write32(gba, base, core->registers[i] + (i == 15) * 4);
            }

            base += pre ? 0 : 4; // Post-increment

            if (first && wb) { // Write back
                core->registers[rn] = base_new;
                first = false;
            }
        }
        ++i;
    }

    if (pc_in_rlist && load) {
        if (s) {
            struct psr spsr;

            spsr = core_spsr_get(core, core->cpsr.mode);
            core_switch_mode(core, spsr.mode);
            core->cpsr = spsr;
        }
        core_reload_pipeline(gba);
    }

    if (mode_switch) { // Roll back to previous mode
        core_switch_mode(core, mode_old);
    }
}