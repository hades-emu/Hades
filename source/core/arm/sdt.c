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
        uint32_t val;
        uint32_t rm;
        uint32_t shift;

        rm = op & 0xF;
        shift = bitfield_get_range(op, 4, 12);
        val = core->registers[rm];

        /*
        ** If R15 (the PC) is used as an operand in a data processing instruction the register is used directly.
        ** The PC value will be the address of the instruction, plus 8 or 12 bytes due to instruction prefetching.
        **   - If the shift amount is specified in the instruction, the PC will be 8 bytes ahead.
        **   - If a register is used to specify the shift amount the PC will be 12 bytes ahead
        */

        if (bitfield_get(shift, 0)) {
            val += (rm == 15) * 4;
            base += (rn == 15) * 4;
        }

        offset = core_compute_shift(core, shift, val, false);
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
    if (bitfield_get(op, 20)) { // Load
        uint32_t val;

        if (bitfield_get(op, 22)) { // Load Byte
            val = mem_read8(gba, effective_addr);
        } else { // Load Word
            val = mem_read32_ror(gba, effective_addr);
        }

        if (!bitfield_get(op, 24) || bitfield_get(op, 21)) {
            core->registers[rn] = addr;
        }

        core->registers[rd] = val;

        // Reload the pipeline of rd is pc
        if (rd == 15) {
            core_reload_pipeline(gba);
        }

    } else { // Store

        if (bitfield_get(op, 22)) { // Store Byte
            mem_write8(gba, effective_addr, core->registers[rd] + (rd == 15) * 4); // TODO FIXME Idle
        } else { // Store word
            mem_write32(gba, effective_addr, core->registers[rd] + (rd == 15) * 4); // TODO FIXME Idle
        }

        if (!bitfield_get(op, 24) || bitfield_get(op, 21)) {
            core->registers[rn] = addr;
        }
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
        offset = core->registers[bitfield_get_range(op, 0, 4)];
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
    if (bitfield_get(op, 20)) { // Load
        uint32_t val;

        switch ((bitfield_get(op, 6) << 1) | bitfield_get(op, 5)) {
            //   0bSH
            case 0b01: // Unsigned Halfword Load
                val = mem_read16(gba, effective_addr);
                break;
            case 0b10: // Signed Byte Load
                val = (int32_t)(int8_t)mem_read8(gba, effective_addr);
                break;
            case 0b11: // Signed Halfword Load
                // (Unligned addresses are a bitch)
                if (bitfield_get(addr, 0)) {
                    val = (int32_t)(int8_t)(uint8_t)mem_read16(gba, effective_addr);
                } else {
                    val = (int32_t)(int16_t)(uint16_t)mem_read16(gba, effective_addr);
                }
               break;
            default:
                unimplemented(HS_CORE, "Sub-operation of \"Halfword and Signed Data Transfer\" not implemented (op=%08x)", op);
                break;
        }

        /*
        ** if bit 24 or bit 21 is set (post-indexing modification or write-through),
        ** we must update the base register with the calculated address.
        */
        if (!bitfield_get(op, 24) || bitfield_get(op, 21)) {
            core->registers[rn] = addr;
        }

        core->registers[rd] = val;

    } else { // Store
        switch ((bitfield_get(op, 6) << 1) | bitfield_get(op, 5)) {
            //   0bSH
            case 0b01: // Unsigned Halfword Store
                mem_write16(gba, effective_addr, core->registers[rd]);
                break;
            default:
                unimplemented(HS_CORE, "Sub-operation of \"Halfword and Signed Data Transfer\" not implemented (op=%08x)", op);
                break;
        }

        /*
        ** if bit 24 or bit 21 is set (post-indexing modification or write-through),
        ** we must update the base register with the calculated address.
        */
        if (!bitfield_get(op, 24) || bitfield_get(op, 21)) {
            core->registers[rn] = addr;
        }
    }
}