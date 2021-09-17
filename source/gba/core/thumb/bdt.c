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

/*
** Execute the PUSH instruction.
*/
void
core_thumb_push(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    ssize_t i;

    core = &gba->core;
    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;

    /* Edge case: if rlist is empty, sp is decreased by 0x40 and r15 is stored instead */
    if (!bitfield_get_range(op, 0, 9)) {
        core->sp -= 0x40;
        mem_write32(gba, core->sp, core->pc, NON_SEQUENTIAL);
        return ;
    }

    /* Push LR */
    if (bitfield_get(op, 8)) {
        core->sp -= 4;
        mem_write32(gba, core->sp, core->lr, NON_SEQUENTIAL);
    }

    for (i = 7; i >= 0; --i) {
        if (bitfield_get(op, i)) {
            core->sp -= 4;
            mem_write32(gba, core->sp, core->registers[i], SEQUENTIAL);
        }
    }
}

/*
** Execute the POP instruction.
*/
void
core_thumb_pop(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    enum access_type access_type;
    ssize_t i;

    core = &gba->core;
    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;

    /* Edge case: if rlist is empty, r15 is loaded instead and sp is increased by 0x40 */
    if (!bitfield_get_range(op, 0, 9)) {
        core->pc = mem_read32(gba, core->sp, NON_SEQUENTIAL);
        core_reload_pipeline(gba);
        core->sp += 0x40;
        return ;
    }

    access_type = NON_SEQUENTIAL;

    for (i = 0; i < 8; ++i) {
        if (bitfield_get(op, i)) {
            core->registers[i] = mem_read32(gba, core->sp, access_type);
            core->sp += 4;
            access_type = SEQUENTIAL;
        }
    }

    core_idle(gba);

    /* Pop PC */
    if (bitfield_get(op, 8)) {
        core->pc = mem_read32(gba, core->sp, access_type);
        core->sp += 4;
        core_reload_pipeline(gba);
    }
}

/*
** Execute the STMIA (Store Multiple Increment After) instruction.
*/
void
core_thumb_stmia(
    struct gba *gba,
    uint16_t op
) {
    bool first;
    struct core *core;
    enum access_type access_type;
    uint32_t count;
    uint32_t addr;
    uint32_t rb;
    ssize_t i;

    count = 0;
    rb = bitfield_get_range(op, 8, 11);
    core = &gba->core;
    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;

    /*
    ** Edge case: if rlist is empty, r15 is stored instead and rb is increased by 0x40
    ** (as if all registered were pushed).
    */
    if (!bitfield_get_range(op, 0, 8)) {
        mem_write32(gba, core->registers[rb], core->pc, NON_SEQUENTIAL);
        core->registers[rb] += 0x40;
        return ;
    }

    for (i = 0; i < 8; ++i) {
        if (bitfield_get(op, i)) {
            count += 4;
        }
    }

    first = true;
    addr = core->registers[rb];

    /*
    ** Edge case if Rb is included in the rlist:
    ** We must store the OLD base if Rb is the FIRST entry in Rlist
    ** and otherwise store the NEW base.
    */

    access_type = NON_SEQUENTIAL;
    for (i = 0; i < 8; ++i) {
        if (bitfield_get(op, i)) {
            mem_write32(gba, addr, core->registers[i], access_type);
            addr += 4;
            access_type = SEQUENTIAL;

            if (first) {
                core->registers[rb] += count;
                first = false;
            }
        }
    }
}

/*
** Execute the LDMIA (Load Multiple Increment After) instruction.
*/
void
core_thumb_ldmia(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    enum access_type access_type;
    uint32_t count;
    uint32_t addr;
    uint32_t rb;
    ssize_t i;

    count = 0;
    core = &gba->core;
    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;
    rb = bitfield_get_range(op, 8, 11);

    /*
    ** Edge case: if rlist is empty, r15 is loaded instead and rb is increased by 0x40
    ** (as if all registered were pushed).
    */
    if (!bitfield_get_range(op, 0, 8)) {
        core->pc = mem_read32(gba, core->registers[rb], NON_SEQUENTIAL);
        core_reload_pipeline(gba);
        core->registers[rb] += 0x40;
        return ;
    }

    for (i = 0; i < 8; ++i) {
        if (bitfield_get(op, i)) {
            count += 4;
        }
    }

    addr = core->registers[rb];
    core->registers[rb] += count;
    access_type = NON_SEQUENTIAL;
    core_idle(gba);

    for (i = 0; i < 8; ++i) {
        if (bitfield_get(op, i)) {
            core->registers[i] = mem_read32(gba, addr, access_type);
            addr += 4;
            access_type = SEQUENTIAL;
        }
    }
}