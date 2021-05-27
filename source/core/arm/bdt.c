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

/*
** Execute the Block Data Transfer kind of instructions (push/pop).
*/
void
core_arm_bdt(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    bool p; // Pre-indexing
    bool u; // Up
    bool s; // Force PSR/User-mode
    bool w; // Write-back
    bool l; // Load
    uint32_t rn;
    uint32_t base;
    int32_t base_step;
    int32_t reg;
    int32_t reg_start;
    int32_t reg_step;

    core = &gba->core;

    p = bitfield_get(op, 24);
    u = bitfield_get(op, 23);
    s = bitfield_get(op, 22);
    w = bitfield_get(op, 21);
    l = bitfield_get(op, 20);
    rn = bitfield_get_range(op, 16, 20);

    if (s) {
        unimplemented(HS_CORE, "Block Data Transfer does not support the PSR & force user bit.");
    }

    base = core->registers[rn];

    if (u) { // Upward
        base_step = 4;
        reg_start = 0;
        reg_step = 1;
    } else { // Downard
        base_step = -4;
        reg_start = 15;
        reg_step = -1;
    }

    if (p) { // Pre-indexing
        base += base_step;
    }

    reg = reg_start;
    while (reg < 16 && reg >= 0) {
        // Transfer register
        if (bitfield_get(op, reg)) {
            if (l) { // Load
                hs_logln(HS_DEBUG, "Loading the content of %08x to r%i", base, reg);
                core->registers[reg] = mem_read32(gba, base);
            } else { // Store
                hs_logln(HS_DEBUG, "Storing the content of r%i to %08x", reg, base);
                mem_write32(gba, base, core->registers[reg]);
            }
            base += base_step;
        }
        reg += reg_step;
    }

    if (w) {
        if (p) {
            base -= base_step;
        }
        core->registers[rn] = base;
    }

    // Reload pipeline if we write to r15 (FIXME)
    if (l && bitfield_get(op, 15)) { // Write to PC
        core->cpsr.thumb = core->pc & 0b1;
        core->pc = core->pc & 0xFFFFFFFE;
        core_reload_pipeline(gba);
    }
}