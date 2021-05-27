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
** Execute the Single Data Transfer kind of instructions.
*/
void
core_arm_sdt(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t effective_addr;
    uint32_t base;
    uint32_t addr;
    uint32_t offset;
    uint32_t rd;
    uint32_t rn;

    rd = bitfield_get_range(op, 12, 16);
    rn = bitfield_get_range(op, 16, 20);

    core = &gba->core;
    base = core->registers[rn];
    offset = 0;

    /*
    ** If bit 25 is *not* set, the offset is an immediate value ROR-shifted by a certain amount.
    ** Otherwise, it is derived from a register shifted by a certain amount.
    */
    if (bitfield_get(op, 25)) {
        uint32_t rm;
        uint32_t shift;

        rm = op & 0xF;
        shift = bitfield_get_range(op, 4, 12);
        offset = core_compute_shift(core, shift, core->registers[rm], false);
    } else {
        offset = bitfield_get_range(op, 0, 12);
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
    switch ((bitfield_get(op, 20) << 1) | bitfield_get(op, 22)) {
        case 0b00: // Store word
            mem_write32(gba, effective_addr, core->registers[rd]);
            break;
        case 0b01: // Store byte
            mem_write8(gba, effective_addr, core->registers[rd]);
            break;
        case 0b10: // Load word
            core->registers[rd] = mem_read32(gba, effective_addr);
            break;
        case 0b11: // Load byte
            core->registers[rd] = mem_read8(gba, effective_addr);
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

/*
** Execute the Halfword and Signed Data Transfer kind of instructions.
*/
void
core_arm_hsdt(
    struct gba *gba,
    uint32_t op
) {
    struct core *core;
    uint32_t effective_addr;
    uint32_t base;
    uint32_t addr;
    uint32_t offset;
    uint32_t rd;
    uint32_t rn;

    rd = bitfield_get_range(op, 12, 16);
    rn = bitfield_get_range(op, 16, 20);

    core = &gba->core;
    base = core->registers[rn];
    offset = 0;

    /*
    ** If bit 22 is set, the offset is an immediate value.
    ** Otherwise, it is derived from a register shifted by a certain amount.
    */
    if (bitfield_get(op, 22)) {
        offset = (bitfield_get_range(op, 8, 12) << 4) | bitfield_get_range(op, 0, 4);
    } else {
        uint32_t rm;

        rm = op & 0xF;
        offset = core->registers[rm];
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
    ** Bit 20 indicates if it is a load or a store, bit 5 and 6 indicate the operation.
    */
    hs_logln(HS_CORE, "SHL=%i%i%i", bitfield_get(op, 6), bitfield_get(op, 5), bitfield_get(op, 20));
    switch ((bitfield_get(op, 6) << 2) | (bitfield_get(op, 5) << 1) | bitfield_get(op, 20)) {
        //   0bSHL
        case 0b010: // Unsigned Halfword store
            mem_write16(gba, effective_addr, core->registers[rd]);
            break;
        case 0b011: // Unsigned Halfword load
            core->registers[rd] = mem_read16(gba, effective_addr);
            break;
        case 0b100:
        case 0b110:
            panic(HS_CORE, "Halfword and Signed Data Transfer: the sign-bit and the load bit are both set.");
            break;
        default:
            unimplemented(HS_CORE, "Sub-operation of \"Halfword and Signed Data Transfer\" not implemented");
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