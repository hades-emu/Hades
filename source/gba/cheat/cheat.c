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

static void cheat_hook_impl(struct gba *gba, struct cheat_bin const *bin);

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
            case CHEAT_INSN_ASSIGN:          dbgln(HS_CHEAT, "    - %zu | Assign:          | [0x%08x] = 0x%0*x", i, insn->assign.addr, insn->assign.width * 2, insn->assign.value); break;
            case CHEAT_INSN_INDIRECT_ASSIGN: dbgln(HS_CHEAT, "    - %zu | Indirect Assign: | [[0x%08x]] = 0x%0*x", i, insn->ind_assign.addr, insn->ind_assign.width * 2, insn->ind_assign.value); break;
            case CHEAT_INSN_ADD_ASSIGN:      dbgln(HS_CHEAT, "    - %zu | Add Assign:      | [0x%08x] = [0x%08x] + 0x%0*x", i, insn->add_assign.addr, insn->add_assign.addr, insn->add_assign.width * 2, insn->add_assign.value); break;
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
        dbgln(HS_CHEAT, "    - %zu | [%08x] = %0*x", i, patch->addr, patch->width * 2, patch->value);
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

static
void
cheat_hook_impl(
    struct gba *gba,
    struct cheat_bin const *bin
) {
    size_t i;

    for (i = 0; i < bin->insns.len; ++i) {
        struct cheat_insn *insn;

        insn = &bin->insns.list[i];

        switch (insn->kind) {
            case CHEAT_INSN_ASSIGN: {
                size_t repeat;
                uint32_t addr;

                addr = insn->assign.addr;

                for (repeat = 0; repeat <= insn->assign.repeat; ++repeat) {
                    switch (insn->assign.width) {
                        case 1: mem_write8_raw(gba, addr, insn->assign.value); break;
                        case 2: mem_write16_raw(gba, addr, insn->assign.value); break;
                        case 4: mem_write32_raw(gba, addr, insn->assign.value); break;
                        default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->assign.width);
                    }
                    addr += insn->assign.width;
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
