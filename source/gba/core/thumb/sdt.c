/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba/gba.h"

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

    core = &gba->core;
    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    offset = bitfield_get_range(op, 6, 11);

    switch ((bitfield_get(op, 11) << 1) | bitfield_get(op, 12)) {
        case 0b00: // Store word
            mem_write32(gba, core->registers[rb] + (offset << 2), core->registers[rd], NON_SEQUENTIAL);
            break;
        case 0b01: // Store byte
            mem_write8(gba, core->registers[rb] + offset, core->registers[rd], NON_SEQUENTIAL);
            break;
        case 0b10: // Load word
            core->registers[rd] = mem_read32_ror(gba, core->registers[rb] + (offset << 2), NON_SEQUENTIAL);
            core_idle(gba);
            break;
        case 0b11: // Load byte
            core->registers[rd] = mem_read8(gba, core->registers[rb] + offset, NON_SEQUENTIAL);
            core_idle(gba);
            break;
    }

    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;
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

    core = &gba->core;
    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    ro = bitfield_get_range(op, 6, 9);

    switch ((bitfield_get(op, 11) << 1) | bitfield_get(op, 10)) {
        case 0b00: // Store word
            mem_write32(gba, core->registers[rb] + core->registers[ro], core->registers[rd], NON_SEQUENTIAL);
            break;
        case 0b01: // Store byte
            mem_write8(gba, core->registers[rb] + core->registers[ro], core->registers[rd], NON_SEQUENTIAL);
            break;
        case 0b10: // Load word
            core->registers[rd] = mem_read32_ror(gba, core->registers[rb] + core->registers[ro], NON_SEQUENTIAL);
            core_idle(gba);
            break;
        case 0b11: // Load byte
            core->registers[rd] = mem_read8(gba, core->registers[rb] + core->registers[ro], NON_SEQUENTIAL);
            core_idle(gba);
            break;
    }

    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;
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

    core = &gba->core;
    rd = bitfield_get_range(op, 0, 3);
    rb = bitfield_get_range(op, 3, 6);
    offset = bitfield_get_range(op, 6, 11) << 1;
    l = bitfield_get(op, 11);

    if (l) {
        // LDRH
        core->registers[rd] = mem_read16_ror(gba, core->registers[rb] + offset, NON_SEQUENTIAL);
        core_idle(gba);
    } else {
        // STRH
        mem_write16(gba, core->registers[rb] + offset, (uint16_t)core->registers[rd], NON_SEQUENTIAL);
    }

    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;
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
            mem_write16(gba, addr, core->registers[rd], NON_SEQUENTIAL);
            break;
        case 0b01:
            // Load halfword
            core->registers[rd] = mem_read16_ror(gba, addr, NON_SEQUENTIAL);
            core_idle(gba);
            break;
        case 0b10:
            // Load sign-extended byte
            core->registers[rd] = (int32_t)(int8_t)mem_read8(gba, addr, NON_SEQUENTIAL);
            core_idle(gba);
            break;
        case 0b11:
            // Load sign-extended halfword

            // (Unligned addresses are a bitch)
            if (bitfield_get(addr, 0)) {
                core->registers[rd] = (int32_t)(int8_t)mem_read8(gba, addr, NON_SEQUENTIAL);
            } else {
                core->registers[rd] = (int32_t)(int16_t)(uint16_t)mem_read16_ror(gba, addr, NON_SEQUENTIAL);
            }

            core_idle(gba);
            break;
    }
    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;
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
    core->registers[rd] = mem_read32_ror(gba, (core->pc & 0xFFFFFFFC) + offset, NON_SEQUENTIAL);
    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;
    core_idle(gba);
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

    if (l) { // LDR
        core->registers[rd] = mem_read32_ror(gba, core->sp + offset, NON_SEQUENTIAL);
        core_idle(gba);
    } else { // STR
        mem_write32(gba, core->sp + offset, core->registers[rd], NON_SEQUENTIAL);
    }

    core->pc += 2;
    core->prefetch_access_type = NON_SEQUENTIAL;
}
