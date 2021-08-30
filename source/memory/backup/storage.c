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
#include "gba.h"

/*
** Detect the kind of storage the loaded ROM uses, and open/setup the save file.
**
** NOTE: This is a heuristic and can be wrong, it would be a great idea to provide a way
** to override the decision with a command line argument or a configuration option.
**
** Or even better and start a game database.
**
** NOTE: This function exits on hard failure.
*/
void
mem_backup_storage_init(
    struct gba *gba
) {
    size_t read;

    if (memmem(gba->memory.rom, sizeof(gba->memory.rom), "EEPROM_", 7)) {
        logln(HS_GLOBAL, "Detected EEPROM memory. This memory is unsupported yet.");
        gba->memory.backup_storage_type = BACKUP_EEPROM;
    } else if (memmem(gba->memory.rom, sizeof(gba->memory.rom), "SRAM_", 5)) {
        logln(HS_GLOBAL, "Detected SRAM memory");
        gba->memory.backup_storage_type = BACKUP_SRAM;
        gba->memory.backup_storage_size = SRAM_SIZE;
    } else if (
           memmem(gba->memory.rom, sizeof(gba->memory.rom), "FLASH_", 6)
        || memmem(gba->memory.rom, sizeof(gba->memory.rom), "FLASH512_", 9)
    ) {
        logln(HS_GLOBAL, "Detected Flash 64 kilobytes / 512 kilobits");
        gba->memory.backup_storage_type = BACKUP_FLASH64;
        gba->memory.backup_storage_size = FLASH64_SIZE;
    } else if (memmem(gba->memory.rom, sizeof(gba->memory.rom), "FLASH1M_", 8)) {
        logln(HS_GLOBAL, "Detected Flash 128 kilobytes / 1 megabit");
        gba->memory.backup_storage_type = BACKUP_FLASH128;
        gba->memory.backup_storage_size = FLASH128_SIZE;
    } else {
        logln(HS_GLOBAL, "No backup storage detected. Defaulting to SRAM.");
        gba->memory.backup_storage_type = BACKUP_SRAM;
        gba->memory.backup_storage_size = SRAM_SIZE;
    }

    gba->memory.backup_storage_data = calloc(1, gba->memory.backup_storage_size);
    hs_assert(gba->memory.backup_storage_data);

    /*
    ** The only way, afaik, to open a file in read/write mode, creating it if it
    ** does'nt exist and without truncating it is using the "a+" flag.
    ** Unfortunately, the "a+" flag also forces writes to be at the end of the file
    ** even if we lseek() elsewhere, so there's no other choice but to split this operation
    ** in multiple calls.
    */

    gba->backup_storage_file = fopen(gba->backup_storage_path, "rb+");
    if (gba->backup_storage_file) {
        read = fread(
            gba->memory.backup_storage_data,
            1,
            gba->memory.backup_storage_size,
            gba->backup_storage_file
        );

        if (read != gba->memory.backup_storage_size) {
            logln(
                HS_WARNING,
                "Read %zu out of the %zu expected bytes from %s. Is the save corrupted?",
                read,
                gba->memory.backup_storage_size,
                gba->backup_storage_path
            );
        } else {
            logln(
                HS_GLOBAL,
                "Save data successfully loaded."
            );
        }
    } else {
        logln(
            HS_WARNING,
            "Failed to open the save file. A new one is created instead."
        );

        gba->backup_storage_file = fopen(gba->backup_storage_path, "wb+");

        if (!gba->backup_storage_file) {
            fprintf(stderr, "hades: can't open %s: %s.\n", gba->backup_storage_path, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    gba->memory.backup_storage_dirty = true;
    mem_backup_storage_write_to_disk(gba);
}

/*
** Check if the backup storage memory is dirty, and if it is, saves it on disk.
*/
void
mem_backup_storage_write_to_disk(
    struct gba *gba
) {
    if (gba->backup_storage_file && gba->memory.backup_storage_dirty) {
        fseek(gba->backup_storage_file, 0, SEEK_SET);
        fwrite(gba->memory.backup_storage_data, gba->memory.backup_storage_size, 1, gba->backup_storage_file);
        gba->memory.backup_storage_dirty = false;
        printf("W\n");
    }
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