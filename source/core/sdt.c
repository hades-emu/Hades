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
core_sdt(
    struct core *core,
    uint32_t op
) {
    uint32_t effective_addr;
    uint32_t base;
    uint32_t addr;
    uint32_t offset;
    uint32_t rd;
    uint32_t rn;


    rd = op >> 12 & 0xF;
    rn = op >> 16 & 0xF;

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
        shift = (op >> 4) & 0xFF;
        offset = compute_shift(core, shift, core->registers[rm], false);
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
    if (bitfield_get(op, 20)) { // Load
        if (bitfield_get(op, 22)) { // Byte
            core->registers[rd] = core_mem_read8(core, effective_addr);
            hs_logln(
                CORE,
                "%s <- 0x%08x <- byte [0x%08x]",
                registers_name[rd],
                core->registers[rd],
                effective_addr
            );
        } else { // Word
            core->registers[rd] = core_mem_read16(core, effective_addr);
            hs_logln(
                CORE,
                "%s <- 0x%08x <- word [0x%08x]",
                registers_name[rd],
                core->registers[rd],
                effective_addr
            );
        }
    } else { // Store
        if (bitfield_get(op, 22)) { // Byte
            core_mem_write8(core, effective_addr, core->registers[rd]);
            hs_logln(
                CORE,
                "byte [0x%08x] <- 0x%08x <- %s",
                effective_addr,
                core->registers[rd],
                registers_name[rd]
            );
        } else { // Word
            core_mem_write16(core, effective_addr, core->registers[rd]);
            hs_logln(
                CORE,
                "word [0x%08x] <- 0x%08x <- %s ",
                effective_addr,
                core->registers[rd],
                registers_name[rd]
            );
        }
    }

    /*
    ** If bit 24 or bit 21 is set (post-indexing modification or write-through),
    ** we must update the base register with the calculated address.
    */
    if (!bitfield_get(op, 24) || bitfield_get(op, 21)) {
        core->registers[rn] = addr;
        hs_logln(CORE, "%s <- 0x%08x", registers_name[rn], addr);
    }
}
