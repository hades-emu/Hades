/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "core.h"
#include "hades.h"

/*
** Execute the PUSH instruction.
*/
void
core_thumb_push(
    struct core *core,
    uint16_t op
) {
    ssize_t i;

    // Push LR
    if (bitfield_get(op, 8)) {
        core->sp -= 4;
        core_bus_write32(core, core->sp, core->lr);
    }

    i = 7;
    while (i >= 0) {
        if (bitfield_get(op, i)) {
            core->sp -= 4;
            core_bus_write32(core, core->sp, core->registers[i]);
        }
        --i;
    }
}

/*
** Execute the POP instruction.
*/
void
core_thumb_pop(
    struct core *core,
    uint16_t op
) {
    ssize_t i;

    i = 0;
    while (i < 8) {
        if (bitfield_get(op, i)) {
            core->registers[i] = core_bus_read32(core, core->sp);
            core->sp += 4;
        }
        ++i;
    }

    // Pop LR
    if (bitfield_get(op, 8)) {
        core->pc = core_bus_read32(core, core->sp);
        core_reload_pipeline(core);
        core->sp += 4;

    }
}

/*
** Execute the Load/Store Word/Byte With Immediate Offset instruction.
*/
void
core_thumb_sdt_imm(
    struct core *core,
    uint16_t op
) {
    uint32_t rd;
    uint32_t rb;
    uint32_t offset;


    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    offset = bitfield_get_range(op, 6, 11);

    switch ((bitfield_get(op, 11) << 1) | bitfield_get(op, 12)) {
        case 0b00: // Store word
            core_bus_write32(core, core->registers[rb] + (offset << 2), core->registers[rd]);
            break;
        case 0b01: // Store byte
            core_bus_write8(core, core->registers[rb] + offset, core->registers[rd]);
            break;
        case 0b10: // Load word
            core->registers[rd] = core_bus_read32(core, core->registers[rb] + (offset << 2));
            break;
        case 0b11: // Load byte
            core->registers[rd] = core_bus_read8(core, core->registers[rb] + offset);
            break;
    }
}

/*
** Execute the Load/Store Word/Byte With Register Offset instruction.
*/
void
core_thumb_sdt_reg(
    struct core *core,
    uint16_t op
) {
    uint32_t rd;
    uint32_t rb;
    uint32_t ro;

    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    ro = bitfield_get_range(op, 6, 9);

    switch ((bitfield_get(op, 11) << 1) | bitfield_get(op, 10)) {
        case 0b00: // Store word
            core_bus_write32(core, core->registers[rb] + core->registers[ro], core->registers[rd]);
            break;
        case 0b01: // Store byte
            core_bus_write8(core, core->registers[rb] + core->registers[ro], core->registers[rd]);
            break;
        case 0b10: // Load word
            core->registers[rd] = core_bus_read32(core, core->registers[rb] + core->registers[ro]);
            break;
        case 0b11: // Load byte
            core->registers[rd] = core_bus_read8(core, core->registers[rb] + core->registers[ro]);
            break;
    }
}

/*
** Execute the Load/Store Halfword with Immediate Offset instructions
*/
void
core_thumb_sdt_halfword(
    struct core *core,
    uint16_t op
) {
    uint32_t offset;
    uint32_t rd;
    uint32_t rb;
    bool l;

    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    offset = bitfield_get_range(op, 6, 11) << 1;
    l = bitfield_get(op, 11);

    if (l) {
        // LDRH
        core->registers[rd] = core_bus_read16(core, core->registers[rb] + offset);
    } else {
        // STRH
        core_bus_write16(core, core->registers[rb] + offset, (uint16_t)core->registers[rd]);
    }
}

/*
** Execute the Load/Store Sign-Extended Byte/Halfword with Register Offset instructions.
*/
void
core_thumb_sdt_sign_halfword(
    struct core *core,
    uint16_t op
) {
    uint32_t rd;
    uint32_t rb;
    uint32_t ro;
    uint32_t addr;

    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    ro = bitfield_get_range(op, 6, 9);

    addr = core->registers[rb] + core->registers[ro];

    switch ((bitfield_get(op, 10) << 1) | bitfield_get(op, 11)) {
        case 0b00:
            // Store halfword
            core_bus_write16(core, addr, core->registers[rd]);
            break;
        case 0b01:
            // Load halfword
            core->registers[rd] = core_bus_read16(core, addr);
            break;
        case 0b10:
            // Load sign-extended byte
            core->registers[rd] = (int32_t)(int8_t)core_bus_read8(core, addr);
            break;
        case 0b11:
            // Load sign-extended halfword

            // (Unligned addresses are a bitch)
            if (bitfield_get(addr, 0)) {
                core->registers[rd] = (int32_t)(int8_t)(uint8_t)core_bus_read16(core, addr);
            } else {
                core->registers[rd] = (int32_t)(int16_t)(uint16_t)core_bus_read16(core, addr);
            }
            break;
    }
}

/*
** Execute the pc-relative load instruction
*/
void
core_thumb_ldr_pc(
    struct core *core,
    uint16_t op
) {
    uint32_t rd;
    uint32_t offset;

    rd = bitfield_get_range(op, 8, 11);
    offset = bitfield_get_range(op, 0, 8) << 2;

    core->registers[rd] = core_bus_read32(core, (core->pc & 0xFFFFFFFC) + offset);
}

/*
** Execute the Sp-Relative Load/Store instructions
*/
void
core_thumb_sdt_sp(
    struct core *core,
    uint16_t op
) {
    uint32_t rd;
    uint32_t offset;
    bool l;

    rd = bitfield_get_range(op, 8, 11);
    offset = bitfield_get_range(op, 0, 8) << 2;
    l = bitfield_get(op, 11);

    if (l) {
        // LDT
        core->registers[rd] = core_bus_read32(core, core->sp + offset);
    } else {
        // SDT
        core_bus_write32(core,  core->sp + offset, core->registers[rd]);
    }
}
