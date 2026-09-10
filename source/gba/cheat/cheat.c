/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/cheat.h"

void
cheat_delete(
    struct cheat_bin *bin
) {
    free(bin->rom_patches.list);
    bin->rom_patches.list = NULL;
    bin->rom_patches.capacity = 0;
    bin->rom_patches.len = 0;

    free(bin->insns.list);
    bin->insns.list = NULL;
    bin->insns.capacity = 0;
    bin->insns.len = 0;
}

void
cheat_dump(
    struct cheat_bin const *bin
) {
    size_t i;

    if (bin->hook.active) {
        dbgln(HS_CHEAT, "  - Hook: %08x", bin->hook.bp.ptr);
    } else {
        dbgln(HS_CHEAT, "  - No hook");
    }

    if (bin->insns.len > 0) {
        dbgln(HS_CHEAT, "  - Instructions: ");
    } else {
        dbgln(HS_CHEAT, "  - No instructions");
    }

    for (i = 0; i < bin->insns.len; ++i) {
        struct cheat_insn *insn;

        insn = &bin->insns.list[i];

        switch (insn->kind) {
            case CHEAT_INSN_ASSIGN:          dbgln(HS_CHEAT, "    - %2zu | Assign:          | [0x%08x] = 0x%0*x", i, insn->assign.addr, insn->assign.width * 2, insn->assign.value); break;
            case CHEAT_INSN_INDIRECT_ASSIGN: dbgln(HS_CHEAT, "    - %2zu | Indirect Assign: | [[0x%08x]] = 0x%0*x", i, insn->ind_assign.addr, insn->ind_assign.width * 2, insn->ind_assign.value); break;
            case CHEAT_INSN_ADD_ASSIGN:      dbgln(HS_CHEAT, "    - %2zu | Add Assign:      | [0x%08x] = [0x%08x] + 0x%0*x", i, insn->add_assign.addr, insn->add_assign.addr, insn->add_assign.width * 2, insn->add_assign.value); break;
            case CHEAT_INSN_AND_ASSIGN:      dbgln(HS_CHEAT, "    - %2zu | And Assign:      | [0x%08x] = [0x%08x] & 0x%0*x", i, insn->and_assign.addr, insn->and_assign.addr, insn->and_assign.width * 2, insn->and_assign.value); break;
            case CHEAT_INSN_OR_ASSIGN:       dbgln(HS_CHEAT, "    - %2zu | Or Assign:       | [0x%08x] = [0x%08x] | 0x%0*x", i, insn->or_assign.addr, insn->or_assign.addr, insn->or_assign.width * 2, insn->or_assign.value); break;
            case CHEAT_INSN_IF_EQ:           dbgln(HS_CHEAT, "    - %2zu | If Equal:        | If [0x%08x] == 0x%0*x then", i, insn->cond.addr, insn->cond.width * 2, insn->cond.value); break;
            case CHEAT_INSN_IF_NEQ:          dbgln(HS_CHEAT, "    - %2zu | If Not Equal:    | If [0x%08x] == 0x%0*x then", i, insn->cond.addr, insn->cond.width * 2, insn->cond.value); break;
            case CHEAT_INSN_IF_GT_SIGNED:    dbgln(HS_CHEAT, "    - %2zu | If greater (S):  | If [0x%08x] == 0x%0*x then", i, insn->cond.addr, insn->cond.width * 2, insn->cond.value); break;
            case CHEAT_INSN_IF_LT_SIGNED:    dbgln(HS_CHEAT, "    - %2zu | If lower (S):    | If [0x%08x] == 0x%0*x then", i, insn->cond.addr, insn->cond.width * 2, insn->cond.value); break;
            case CHEAT_INSN_IF_AND:          dbgln(HS_CHEAT, "    - %2zu | If And:          | If [0x%08x] & 0x%0*x then", i, insn->cond.addr, insn->cond.width * 2, insn->cond.value); break;
        }
    }

    if (bin->rom_patches.len > 0) {
        dbgln(HS_CHEAT, "  - ROM Patches: ");
    } else {
        dbgln(HS_CHEAT, "  - No ROM patches");
    }

    for (i = 0; i < bin->rom_patches.len; ++i) {
        struct cheat_rom_patch const *patch;

        patch = &bin->rom_patches.list[i];
        dbgln(HS_CHEAT, "    - %2zu | [0x%08x] = 0x%0*x", i, patch->addr, patch->width * 2, patch->value);
    }
}

void
cheat_process_hooks_at_addr(
    struct gba *gba,
    uint32_t addr
) {
    size_t i;

    for (i = 0; i < gba->cheats.len; ++i) {
        struct cheat_bin *bin;

        bin = &gba->cheats.list[i];


        if (!bin->hook.active || addr != bin->hook.bp.ptr) {
            continue;
        }

        cheat_hook_impl(gba, bin);
    }
}

void
cheat_hook_impl(
    struct gba *gba,
    struct cheat_bin const *bin
) {
    size_t insn_idx;

    for (insn_idx = 0; insn_idx < bin->insns.len; ++insn_idx) {
        struct cheat_insn *insn;

        insn = &bin->insns.list[insn_idx];

        switch (insn->kind) {
            case CHEAT_INSN_ASSIGN: {
                size_t i;
                uint32_t addr;
                uint32_t value;

                addr = insn->assign.addr;
                value = insn->assign.value;

                for (i = 0; i <= insn->assign.repeat; ++i) {
                    switch (insn->assign.width) {
                        case 1: mem_write8_raw(gba, addr, value); break;
                        case 2: mem_write16_raw(gba, addr, value); break;
                        case 4: mem_write32_raw(gba, addr, value); break;
                        default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->assign.width);
                    }
                    addr += insn->assign.addr_offset;
                    value += insn->assign.value_offset;
                }
                break;
            }
            case CHEAT_INSN_INDIRECT_ASSIGN: {
                uint32_t addr;

                addr = insn->ind_assign.addr;
                addr = mem_read32_raw(gba, addr);
                switch (insn->ind_assign.width) {
                    case 1: mem_write8_raw(gba, addr + insn->ind_assign.offset, insn->ind_assign.value); break;
                    case 2: mem_write16_raw(gba, addr + insn->ind_assign.offset, insn->ind_assign.value); break;
                    case 4: mem_write32_raw(gba, addr + insn->ind_assign.offset, insn->ind_assign.value); break;
                    default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->ind_assign.width);
                }
                break;
            }
            case CHEAT_INSN_ADD_ASSIGN: {
                uint32_t addr;

                addr = insn->add_assign.addr;
                switch (insn->add_assign.width) {
                    case 1: mem_write8_raw(gba, addr, mem_read8_raw(gba, addr) + insn->add_assign.value); break;
                    case 2: mem_write16_raw(gba, addr, mem_read16_raw(gba, addr) + insn->add_assign.value); break;
                    case 4: mem_write32_raw(gba, addr, mem_read32_raw(gba, addr) + insn->add_assign.value); break;
                    default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->ind_assign.width);
                }
                break;
            }
            case CHEAT_INSN_AND_ASSIGN: {
                uint32_t addr;

                addr = insn->and_assign.addr;
                switch (insn->and_assign.width) {
                    case 1: mem_write8_raw(gba, addr, mem_read8_raw(gba, addr) & (uint8_t)insn->and_assign.value); break;
                    case 2: mem_write16_raw(gba, addr, mem_read16_raw(gba, addr) & (uint16_t)insn->and_assign.value); break;
                    case 4: mem_write32_raw(gba, addr, mem_read32_raw(gba, addr) & insn->and_assign.value); break;
                    default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->ind_assign.width);
                }
                break;
            }
            case CHEAT_INSN_OR_ASSIGN: {
                uint32_t addr;

                addr = insn->or_assign.addr;
                switch (insn->or_assign.width) {
                    case 1: mem_write8_raw(gba, addr, mem_read8_raw(gba, addr) | (uint8_t)insn->or_assign.value); break;
                    case 2: mem_write16_raw(gba, addr, mem_read16_raw(gba, addr) | (uint16_t)insn->or_assign.value); break;
                    case 4: mem_write32_raw(gba, addr, mem_read32_raw(gba, addr) | insn->or_assign.value); break;
                    default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->ind_assign.width);
                }
                break;
            }
            case CHEAT_INSN_IF_EQ: {
                uint32_t addr;
                bool cond;

                addr = insn->cond.addr;
                switch (insn->cond.width) {
                    case 1: cond = mem_read8_raw(gba, addr) == (uint8_t)insn->cond.value; break;
                    case 2: cond = mem_read16_raw(gba, addr) == (uint16_t)insn->cond.value; break;
                    case 4: cond = mem_read32_raw(gba, addr) == insn->cond.value; break;
                    default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->ind_assign.width);
                }

                if (!cond) {
                    ++insn_idx;
                }
                break;
            }
            case CHEAT_INSN_IF_NEQ: {
                uint32_t addr;
                bool cond;

                addr = insn->cond.addr;
                switch (insn->cond.width) {
                    case 1: cond = mem_read8_raw(gba, addr) != (uint8_t)insn->cond.value; break;
                    case 2: cond = mem_read16_raw(gba, addr) != (uint16_t)insn->cond.value; break;
                    case 4: cond = mem_read32_raw(gba, addr) != insn->cond.value; break;
                    default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->ind_assign.width);
                }

                if (!cond) {
                    ++insn_idx;
                }
                break;
            }
            case CHEAT_INSN_IF_LT_SIGNED: {
                uint32_t addr;
                bool cond;

                addr = insn->cond.addr;
                switch (insn->cond.width) {
                    case 1: cond = (int8_t)mem_read8_raw(gba, addr) < (int8_t)insn->cond.value; break;
                    case 2: cond = (int16_t)mem_read16_raw(gba, addr) < (int16_t)insn->cond.value; break;
                    case 4: cond = (int32_t)mem_read32_raw(gba, addr) < (int32_t)insn->cond.value; break;
                    default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->ind_assign.width);
                }

                if (!cond) {
                    ++insn_idx;
                }
                break;
            }
            case CHEAT_INSN_IF_GT_SIGNED: {
                uint32_t addr;
                bool cond;

                addr = insn->cond.addr;
                switch (insn->cond.width) {
                    case 1: cond = (int8_t)mem_read8_raw(gba, addr) > (int8_t)insn->cond.value; break;
                    case 2: cond = (int16_t)mem_read16_raw(gba, addr) > (int16_t)insn->cond.value; break;
                    case 4: cond = (int32_t)mem_read32_raw(gba, addr) > (int32_t)insn->cond.value; break;
                    default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->ind_assign.width);
                }

                if (!cond) {
                    ++insn_idx;
                }
                break;
            }
            case CHEAT_INSN_IF_AND: {
                uint32_t addr;
                bool cond;

                addr = insn->cond.addr;
                switch (insn->cond.width) {
                    case 1: cond = mem_read8_raw(gba, addr) & (uint8_t)insn->cond.value; break;
                    case 2: cond = mem_read16_raw(gba, addr) & (uint16_t)insn->cond.value; break;
                    case 4: cond = mem_read32_raw(gba, addr) & insn->cond.value; break;
                    default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->ind_assign.width);
                }

                // If cond is true then execute next code means if code is false then skip next code.
                if (!cond) {
                    ++insn_idx;
                }
                break;
            }
        }
    }
}

struct cheat_insn *
cheat_create_insn(
    struct cheat_bin *bin
) {
    struct cheat_insn *insn;

    if (bin->insns.len * sizeof(struct cheat_insn) == bin->insns.capacity) {
        bin->insns.capacity += 16 * sizeof(struct cheat_insn);
        bin->insns.list = realloc(bin->insns.list, bin->insns.capacity);
        hs_assert(bin->insns.list);
    }

    insn = &bin->insns.list[bin->insns.len];
    bin->insns.len += 1;

    memset(insn, 0, sizeof(*insn));

    return insn;
}

void
cheat_create_rom_patch(
    struct cheat_bin *bin,
    uint32_t addr,
    uint32_t val,
    uint32_t width
) {
    struct cheat_rom_patch *patch;

    if (bin->rom_patches.len * sizeof(struct cheat_rom_patch) == bin->rom_patches.capacity) {
        bin->rom_patches.capacity += 16 * sizeof(struct cheat_rom_patch);
        bin->rom_patches.list = realloc(bin->rom_patches.list, bin->rom_patches.capacity);
        hs_assert(bin->rom_patches.list);
    }

    patch = &bin->rom_patches.list[bin->rom_patches.len];
    bin->rom_patches.len += 1;

    patch->addr = addr;
    patch->value = val;
    patch->width = width;
}
