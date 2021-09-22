/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include "gba/gba.h"

size_t backup_storage_sizes[] = {
    [BACKUP_AUTODETECT] = 0,
    [BACKUP_EEPROM] = 0, // TODO
    [BACKUP_SRAM] = SRAM_SIZE,
    [BACKUP_FLASH64] = FLASH64_SIZE,
    [BACKUP_FLASH128] = FLASH128_SIZE,
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
    //size_t read;

    if (array_search(gba->memory.rom, sizeof(gba->memory.rom), "EEPROM_", 7)) {
        logln(HS_GLOBAL, "Detected EEPROM memory. This memory is unsupported yet.");
        gba->memory.backup_storage_type = BACKUP_EEPROM;
    } else if (array_search(gba->memory.rom, sizeof(gba->memory.rom), "SRAM_", 5)) {
        logln(HS_GLOBAL, "Detected SRAM memory");
        gba->memory.backup_storage_type = BACKUP_SRAM;
    } else if (
           array_search(gba->memory.rom, sizeof(gba->memory.rom), "FLASH_", 6)
        || array_search(gba->memory.rom, sizeof(gba->memory.rom), "FLASH512_", 9)
    ) {
        logln(HS_GLOBAL, "Detected Flash 64 kilobytes / 512 kilobits");
        gba->memory.backup_storage_type = BACKUP_FLASH64;
    } else if (array_search(gba->memory.rom, sizeof(gba->memory.rom), "FLASH1M_", 8)) {
        logln(HS_GLOBAL, "Detected Flash 128 kilobytes / 1 megabit");
        gba->memory.backup_storage_type = BACKUP_FLASH128;
    } else {
        logln(HS_GLOBAL, "No backup storage detected. Defaulting to SRAM.");
        gba->memory.backup_storage_type = BACKUP_SRAM;
    }
}

void
mem_backup_storage_init(
    struct gba *gba
) {
    free(gba->memory.backup_storage_data);

    gba->memory.backup_storage_data = calloc(1, backup_storage_sizes[gba->memory.backup_storage_type]);
    hs_assert(gba->memory.backup_storage_data);
}

uint8_t
mem_backup_storage_read8(
    struct gba const *gba,
    uint32_t addr
) {
    switch (gba->memory.backup_storage_type) {
        case BACKUP_EEPROM:
            break;
        case BACKUP_FLASH64:
        case BACKUP_FLASH128:
            return (mem_flash_read8(gba, addr));
            break;
        case BACKUP_SRAM:
            return (gba->memory.backup_storage_data[addr & SRAM_MASK]);
            break;
        default:
            logln(HS_WARNING, "Unsupported backup storage accessed.");
            break;
    }
    return (0);
}

void
mem_backup_storage_write8(
    struct gba *gba,
    uint32_t addr,
    uint8_t val
) {
    gba->memory.backup_storage_dirty = true;

    switch (gba->memory.backup_storage_type) {
        case BACKUP_EEPROM:
            break;
        case BACKUP_FLASH64:
        case BACKUP_FLASH128:
            mem_flash_write8(gba, addr, val);
            break;
        case BACKUP_SRAM:
            gba->memory.backup_storage_data[addr & SRAM_MASK] = val;
            break;
        default:
            logln(HS_WARNING, "Unsupported backup storage accessed.");
            break;
    }
}