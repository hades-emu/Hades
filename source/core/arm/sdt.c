/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "core.h"

/*
** Execute the Single Data Transfer kind of instructions.
*/
void
core_arm_sdt(
    struct core *core,
    uint32_t op
) {
    uint32_t effective_addr;
    uint32_t base;
    uint32_t addr;
    uint32_t offset;
    uint32_t rd;
    uint32_t rn;


    rd = bitfield_get_range(op, 12, 16);
    rn = bitfield_get_range(op, 16, 20);

    base = core->registers[rn];
    offset = 0;

    /*
    ** If bit 25 is *not* set, the offset is an immediate value
    ** Otherwise, it is derived from a register shifted by a certain amount.
    */
    if (bitfield_get(op, 25)) {
        uint32_t rm;
        uint32_t shift;

        rm = op & 0xF;
        shift = bitfield_get_range(op, 4, 12);
        offset = core_compute_shift(core, shift, core->registers[rm], false);
    } else {
        offset = op & 0xFFF;
    }

    /*
    ** If bit 23 is set, the offset must be added to the base.
    ** Otherwise, it must be substracted.
    */
    if (bitfield_get(op, 23)) {
        addr = base + offset;
    } else {
        addr = base - offset;
    }

    /*
    ** If bit 24 is set, we must add the offset before the transfer, or
    ** after otherwise.
    */
    if (bitfield_get(op, 24)) {
        effective_addr = addr;
    } else {
        effective_addr = base;
    }

    /*
    ** Bit 20 indicates if it is a load or a store, bit 22 if it is
    ** a byte or word transfer
    */
    switch (bitfield_get(op, 20) << 1 | bitfield_get(op, 22)) {
        case 0b00: // Store word
            core_bus_write32(core, effective_addr, core->registers[rd]);
            break;
        case 0b01: // Store byte
            core_bus_write8(core, effective_addr, core->registers[rd]);
            break;
        case 0b10: // Load word
            core->registers[rd] = core_bus_read32(core, effective_addr);
            break;
        case 0b11: // Load byte
            core->registers[rd] = core_bus_read8(core, effective_addr);
            break;
    }

    /*
    ** If bit 24 or bit 21 is set (post-indexing modification or write-through),
    ** we must update the base register with the calculated address.
    */
    if (!bitfield_get(op, 24) || bitfield_get(op, 21)) {
        core->registers[rn] = addr;
    }
}
