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

static void cheat_hook_impl(struct gba *gba, struct cheat_bin const *cheat);

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
cheat_process_hooks_at_addr(
    struct gba *gba,
    uint32_t addr
) {
    size_t i;

    for (i = 0; i < gba->cheats.len; ++i) {
        struct cheat_bin *cheat;

        cheat = &gba->cheats.list[i];

        if (!cheat->hook.active || addr != cheat->hook.bp.ptr) {
            continue;
        }

        cheat_hook_impl(gba, cheat);
    }
}

static
void
cheat_hook_impl(
    struct gba *gba,
    struct cheat_bin const *cheat
) {
    size_t i;

    for (i = 0; i < cheat->insns.len; ++i) {
        struct cheat_insn *insn;
        uint32_t addr;

        insn = &cheat->insns.list[i];
        addr = insn->addr;

        switch (insn->kind) {
            case CHEAT_INSN_ASSIGN: {
                size_t repeat;

                for (repeat = 0; repeat <= insn->repeat; ++repeat) {
                    switch (insn->width) {
                        case 1: mem_write8_raw(gba, addr, insn->value); break;
                        case 2: mem_write16_raw(gba, addr, insn->value); break;
                        case 4: mem_write32_raw(gba, addr, insn->value); break;
                        default: panic(HS_CORE, "Invalid cheat insn width: %u", insn->width);
                    }
                    addr += insn->width;
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
