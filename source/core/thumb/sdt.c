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

    /* Push LR */
    if (bitfield_get(op, 8)) {
        core->sp -= 4;
        mem_write32(core->memory, core->sp, core->lr);
    }

    i = 7;
    while (i >= 0) {
        if (bitfield_get(op, i)) {
            core->sp -= 4;
            mem_write32(core->memory, core->sp, core->registers[i]);
        }
        --i;
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
    ssize_t i;

    core = &gba->core;

    i = 0;
    while (i < 8) {
        if (bitfield_get(op, i)) {
            core->registers[i] = mem_read32(core->memory, core->sp);
            core->sp += 4;
        }
        ++i;
    }

    /* Pop PC */
    if (bitfield_get(op, 8)) {
        core->pc = mem_read32(core->memory, core->sp);
        core_reload_pipeline(core);
        core->sp += 4;

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
    struct core *core;
    uint32_t count;
    uint32_t addr;
    uint32_t rb;
    ssize_t i;

    count = 0;
    core = &gba->core;
    rb = bitfield_get_range(op, 8, 11);

    i = 0;
    while (i < 8) {
        if (bitfield_get(op, i)) {
            count += 4;
        }
        ++i;
    }

    addr = core->registers[rb];
    core->registers[rb] += count;

    i = 0;
    while (i < 8) {
        if (bitfield_get(op, i)) {
            mem_write32(core->memory, addr, core->registers[i]);
            addr += 4;
        }
        ++i;
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
    uint32_t count;
    uint32_t addr;
    uint32_t rb;
    ssize_t i;

    count = 0;
    core = &gba->core;
    rb = bitfield_get_range(op, 8, 11);

    i = 0;
    while (i < 8) {
        if (bitfield_get(op, i)) {
            count += 4;
        }
        ++i;
    }

    addr = core->registers[rb];
    core->registers[rb] += count;

    i = 0;
    while (i < 8) {
        if (bitfield_get(op, i)) {
            core->registers[i] = mem_read32(core->memory, addr);
            addr += 4;
        }
        ++i;
    }
}

/*
** Execute the Load/Store Word/Byte With Immediate Offset instruction.
*/
void
core_thumb_sdt_imm(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t rb;
    uint32_t offset;

    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    offset = bitfield_get_range(op, 6, 11);
    core = &gba->core;

    switch ((bitfield_get(op, 11) << 1) | bitfield_get(op, 12)) {
        case 0b00: // Store word
            mem_write32(core->memory, core->registers[rb] + (offset << 2), core->registers[rd]);
            break;
        case 0b01: // Store byte
            mem_write8(core->memory, core->registers[rb] + offset, core->registers[rd]);
            break;
        case 0b10: // Load word
            core->registers[rd] = mem_read32(core->memory, core->registers[rb] + (offset << 2));
            break;
        case 0b11: // Load byte
            core->registers[rd] = mem_read8(core->memory, core->registers[rb] + offset);
            break;
    }
}

/*
** Execute the Load/Store Word/Byte With Register Offset instruction.
*/
void
core_thumb_sdt_wb_reg(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t rb;
    uint32_t ro;

    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    ro = bitfield_get_range(op, 6, 9);
    core = &gba->core;

    switch ((bitfield_get(op, 11) << 1) | bitfield_get(op, 10)) {
        case 0b00: // Store word
            mem_write32(core->memory, core->registers[rb] + core->registers[ro], core->registers[rd]);
            break;
        case 0b01: // Store byte
            mem_write8(core->memory, core->registers[rb] + core->registers[ro], core->registers[rd]);
            break;
        case 0b10: // Load word
            core->registers[rd] = mem_read32(core->memory, core->registers[rb] + core->registers[ro]);
            break;
        case 0b11: // Load byte
            core->registers[rd] = mem_read8(core->memory, core->registers[rb] + core->registers[ro]);
            break;
    }
}

/*
** Execute the Load/Store Halfword with Immediate Offset instructions
*/
void
core_thumb_sdt_h_imm(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t offset;
    uint32_t rd;
    uint32_t rb;
    bool l;

    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    offset = bitfield_get_range(op, 6, 11) << 1;
    l = bitfield_get(op, 11);
    core = &gba->core;

    if (l) {
        // LDRH
        core->registers[rd] = mem_read16(core->memory, core->registers[rb] + offset);
    } else {
        // STRH
        mem_write16(core->memory, core->registers[rb] + offset, (uint16_t)core->registers[rd]);
    }
}

/*
** Execute the Load/Store Sign-Extended Byte/Halfword with Register Offset instructions.
*/
void
core_thumb_sdt_sbh_reg(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t rb;
    uint32_t ro;
    uint32_t addr;

    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    ro = bitfield_get_range(op, 6, 9);

    core = &gba->core;
    addr = core->registers[rb] + core->registers[ro];

    switch ((bitfield_get(op, 10) << 1) | bitfield_get(op, 11)) {
        case 0b00:
            // Store halfword
            mem_write16(core->memory, addr, core->registers[rd]);
            break;
        case 0b01:
            // Load halfword
            core->registers[rd] = mem_read16(core->memory, addr);
            break;
        case 0b10:
            // Load sign-extended byte
            core->registers[rd] = (int32_t)(int8_t)mem_read8(core->memory, addr);
            break;
        case 0b11:
            // Load sign-extended halfword

            // (Unligned addresses are a bitch)
            if (bitfield_get(addr, 0)) {
                core->registers[rd] = (int32_t)(int8_t)(uint8_t)mem_read16(core->memory, addr);
            } else {
                core->registers[rd] = (int32_t)(int16_t)(uint16_t)mem_read16(core->memory, addr);
            }
            break;
    }
}

/*
** Execute the pc-relative load instruction
*/
void
core_thumb_ldr_pc(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t offset;

    rd = bitfield_get_range(op, 8, 11);
    offset = bitfield_get_range(op, 0, 8) << 2;

    core = &gba->core;
    core->registers[rd] = mem_read32(core->memory, (core->pc & 0xFFFFFFFC) + offset);
}

/*
** Execute the Sp-Relative Load/Store instructions
*/
void
core_thumb_sdt_sp(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t rd;
    uint32_t offset;
    bool l;

    rd = bitfield_get_range(op, 8, 11);
    offset = bitfield_get_range(op, 0, 8) << 2;
    l = bitfield_get(op, 11);
    core = &gba->core;

    if (l) {
        // LDR
        core->registers[rd] = mem_read32(core->memory, core->sp + offset);
    } else {
        // STR
        mem_write32(core->memory,  core->sp + offset, core->registers[rd]);
    }
}
