/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

/*
** References:
**   - https://dillonbeliveau.com/2020/06/05/GBA-FLASH.html
**   - https://densinh.github.io/DenSinH/emulation/2021/02/01/gba-eeprom.html
*/

#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include "gba/gba.h"
#include "gba/db.h"

size_t backup_storage_sizes[] = {
    [BACKUP_NONE] = 0,
    [BACKUP_EEPROM_4K] = EEPROM_4K_SIZE,
    [BACKUP_EEPROM_64K] = EEPROM_64K_SIZE,
    [BACKUP_SRAM] = SRAM_SIZE,
    [BACKUP_FLASH64] = FLASH64_SIZE,
    [BACKUP_FLASH128] = FLASH128_SIZE,
};

static
char const *backup_storage_names[] = {
    [BACKUP_EEPROM_4K] = "EEPROM 4K",
    [BACKUP_EEPROM_64K] = "EEPROM 64K",
    [BACKUP_SRAM] = "SRAM",
    [BACKUP_FLASH64] = "FLASH 64K",
    [BACKUP_FLASH128] = "FLASH 128K",
};

static
char *backup_storage_sources_str[] = {
    [BACKUP_SOURCE_AUTO_DETECT] = "auto-detect",
    [BACKUP_SOURCE_MANUAL]      = "manual",
    [BACKUP_SOURCE_DATABASE]    = "database",
};

/*
** Detect the kind of storage the loaded ROM uses, and open/setup the save file.
**
** NOTE: This is a heuristic and can be wrong, it would be a great idea to provide a way
** to override the decision with a command line argument or a configuration option.
**
** Or even better and start a game database.
*/
void
mem_backup_storage_detect(
    struct gba *gba
) {
    /* Prioritize the game database. */
    if (gba->game_entry) {
        gba->memory.backup_storage.type = gba->game_entry->storage;
        gba->memory.backup_storage.source = BACKUP_SOURCE_DATABASE;
        return ;
    }

    gba->memory.backup_storage.source = BACKUP_SOURCE_AUTO_DETECT;

    /* Auto-detection algorithm are very simple: they look for a bunch of strings in the game's ROM. */
    if (array_search(gba->memory.rom, sizeof(gba->memory.rom), "EEPROM_V", 7)) {
        logln(HS_INFO, "Detected EEPROM 64K memory.");
        logln(HS_WARNING, "If you are having issues with corrupted saves, try EEPROM 8K instead.");
        gba->memory.backup_storage.type = BACKUP_EEPROM_64K;
    } else if (
           array_search(gba->memory.rom, sizeof(gba->memory.rom), "SRAM_V", 5)
        || array_search(gba->memory.rom, sizeof(gba->memory.rom), "SRAM_F_V", 5)
    ) {
        logln(HS_INFO, "Detected SRAM memory");
        gba->memory.backup_storage.type = BACKUP_SRAM;
    } else if (array_search(gba->memory.rom, sizeof(gba->memory.rom), "FLASH1M_V", 8)) {
        logln(HS_INFO, "Detected Flash 128 kilobytes / 1 megabit");
        gba->memory.backup_storage.type = BACKUP_FLASH128;
    } else if (
           array_search(gba->memory.rom, sizeof(gba->memory.rom), "FLASH_V", 6)
        || array_search(gba->memory.rom, sizeof(gba->memory.rom), "FLASH512_V", 9)
    ) {
        logln(HS_INFO, "Detected Flash 64 kilobytes / 512 kilobits");
        gba->memory.backup_storage.type = BACKUP_FLASH64;
    } else {
        gba->memory.backup_storage.type = BACKUP_NONE;
    }
}

void
mem_backup_storage_init(
    struct gba *gba
) {
    free(gba->memory.backup_storage.data);

    if (gba->memory.backup_storage.type > BACKUP_NONE) {
        logln(
            HS_INFO,
            "Backup memory is %s%s%s (%s).",
            g_light_magenta,
            backup_storage_names[gba->memory.backup_storage.type],
            g_reset,
            backup_storage_sources_str[gba->memory.backup_storage.source]
        );
    } else {
        logln(HS_INFO, "No backup storage (%s).", backup_storage_sources_str[gba->memory.backup_storage.source]);
    }

    if (   gba->memory.backup_storage.type == BACKUP_EEPROM_4K
        || gba->memory.backup_storage.type == BACKUP_EEPROM_64K
    ) {
        struct eeprom *eeprom;

        /*
        ** Those are masks applied to the address of any ROM data transfers
        ** to know if it's targetting the ROM or the EEPROM.
        ** They depend on the ROM's size.
        **
        ** A data transfer is going to the EEPROM iff (addr & eeprom.mask) == eeprom.range.
        */
        eeprom = &gba->memory.backup_storage.chip.eeprom;
        if (gba->memory.rom_size > 16 * 1024 * 1024) {
            eeprom->mask = 0x01FFFF00;
            eeprom->range = 0x01FFFF00;
        } else {
            eeprom->mask = 0xFF000000;
            eeprom->range = 0x0d000000;
        }

        if (gba->memory.backup_storage.type == BACKUP_EEPROM_4K) {
            eeprom->address_mask = EEPROM_4K_ADDR_MASK;
            eeprom->address_len = EEPROM_4K_ADDR_LEN;
        } else { // EEPROM_64K
            eeprom->address_mask = EEPROM_64K_ADDR_MASK;
            eeprom->address_len = EEPROM_64K_ADDR_LEN;
        }
    }

    if (gba->memory.backup_storage.type > BACKUP_NONE) {
        gba->memory.backup_storage.data = calloc(1, backup_storage_sizes[gba->memory.backup_storage.type]);
        hs_assert(gba->memory.backup_storage.data);
    } else {
        gba->memory.backup_storage.data = NULL;
    }
}

uint8_t
mem_backup_storage_read8(
    struct gba const *gba,
    uint32_t addr
) {
    switch (gba->memory.backup_storage.type) {
        case BACKUP_FLASH64:
        case BACKUP_FLASH128:
            return (mem_flash_read8(gba, addr));
            break;
        case BACKUP_SRAM:
            return (gba->memory.backup_storage.data[addr & SRAM_MASK]);
            break;
        default:
            return (0);
    }
}

void
mem_backup_storage_write8(
    struct gba *gba,
    uint32_t addr,
    uint8_t val
) {
    switch (gba->memory.backup_storage.type) {
        case BACKUP_FLASH64:
        case BACKUP_FLASH128:
            mem_flash_write8(gba, addr, val);
            break;
        case BACKUP_SRAM:
            gba->memory.backup_storage.data[addr & SRAM_MASK] = val;
            gba->memory.backup_storage.dirty = true;
            break;
        default:
            break;
    }
}
