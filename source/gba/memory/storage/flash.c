/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/memory.h"

uint8_t
mem_flash_read8(
    struct gba const *gba,
    uint32_t addr
) {
    struct flash const *flash;

    flash = &gba->memory.flash;
    addr &= FLASH_MASK;

    if (flash->identity_mode) {
        /* Use Panasonic (0x1b32) for Flash 64k and Sanyo (0x1362) for Flash 128k. */
        if (addr == 0x0) {
            return (gba->memory.backup_storage_type == BACKUP_FLASH64 ? 0x32 : 0x62);
        } else if (addr == 0x1) {
            return (gba->memory.backup_storage_type == BACKUP_FLASH64 ? 0x1b : 0x13);
        }
    }
    return (gba->memory.backup_storage_data[addr + flash->bank * FLASH64_SIZE]);
}

void
mem_flash_write8(
    struct gba *gba,
    uint32_t addr,
    uint8_t val
) {
    struct flash *flash;

    flash = &gba->memory.flash;
    addr &= FLASH_MASK;

    if (addr == 0x5555 && val == 0xAA && flash->state == FLASH_STATE_READY) {
        flash->state = FLASH_STATE_CMD_1;
    } else if (addr == 0x2AAA && val == 0x55 && flash->state == FLASH_STATE_CMD_1) {
        flash->state = FLASH_STATE_CMD_2;
    } else if (addr == 0x5555 && flash->state == FLASH_STATE_CMD_2) {
        flash->state = FLASH_STATE_READY;
        switch (val) {
            case FLASH_CMD_ENTER_IDENTITY:      flash->identity_mode = true; break;
            case FLASH_CMD_EXIT_IDENTITY:       flash->identity_mode = false; break;
            case FLASH_CMD_PREP_ERASE:          flash->state = FLASH_STATE_ERASE; break;
            case FLASH_CMD_ERASE_CHIP: {
                if (flash->state == FLASH_STATE_ERASE) {
                    memset(gba->memory.backup_storage_data, 0xFF, backup_storage_sizes[gba->memory.backup_storage_type]);
                }
                break;
            };
            case FLASH_CMD_WRITE:               flash->state = FLASH_STATE_WRITE; break;
            case FLASH_CMD_SET_BANK: {
                if (gba->memory.backup_storage_type == BACKUP_FLASH128) {
                    flash->state = FLASH_STATE_BANK;
                }
                break;
            };
        }
    } else if (flash->state == FLASH_STATE_ERASE && !(addr & ~0xF000) && val == FLASH_CMD_ERASE_SECTOR) {
        // Erase the desired sector

        addr &= 0xF000;
        memset(gba->memory.backup_storage_data + addr + flash->bank * FLASH64_SIZE, 0xFF, 0x1000);
        flash->state = FLASH_STATE_READY;
    } else if (flash->state == FLASH_STATE_WRITE) {
        gba->memory.backup_storage_data[addr + flash->bank * FLASH64_SIZE] = val;
        flash->state = FLASH_STATE_READY;
    } else if (flash->state == FLASH_STATE_BANK && addr == 0x0) {
        flash->bank = val;
        flash->state = FLASH_STATE_READY;
    }
}