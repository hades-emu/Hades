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

uint8_t
mem_eeprom_read8(
    struct gba *gba
) {
    struct eeprom *eeprom;

    eeprom = &gba->memory.eeprom;

    if (eeprom->cmd == EEPROM_CMD_READ) {
        if (eeprom->state == EEPROM_STATE_TRANSFER_JUNK) {
            eeprom->transfer_len++;

            if (eeprom->transfer_len >= 4) {
                eeprom->transfer_len = 0; // Reset for next transfer
                eeprom->state = EEPROM_STATE_TRANSFER_DATA;
            }
            return (0);
        } else if (eeprom->state == EEPROM_STATE_TRANSFER_DATA) {
            bool value;

            value = (eeprom->transfer_data >> 63);
            eeprom->transfer_data <<= 1;
            eeprom->transfer_len++;

            if (eeprom->transfer_len >= 64) {
                eeprom->transfer_len = 0; // Reset for next transfer
                eeprom->state = EEPROM_STATE_READY;
            }
            return (value);
        }
    }

    /*
    ** After a write transfer, games likely check if the transfer is complete.
    ** They do this by reading from the EEPROM and waiting until it returns 1.
    **   - Dennis H
    */
    return (1);
}

void
mem_eeprom_write8(
    struct gba *gba,
    bool val
) {
    struct eeprom *eeprom;

    eeprom = &gba->memory.eeprom;

    switch (eeprom->state) {
        case EEPROM_STATE_READY: {
            if (val) {
                eeprom->state = EEPROM_STATE_CMD;
            }
            break;
        };
        case EEPROM_STATE_CMD: {
            eeprom->cmd = val ? EEPROM_CMD_READ : EEPROM_CMD_WRITE;
            eeprom->state = EEPROM_STATE_TRANSFER_ADDR;
            eeprom->transfer_address = 0;
            break;
        };
        case EEPROM_STATE_TRANSFER_ADDR: {
            eeprom->transfer_address <<= 1;
            eeprom->transfer_address |= val;
            eeprom->transfer_len++;

            if (eeprom->transfer_len >= eeprom->address_len) {
                eeprom->transfer_address *= 8; // All addresses are a multiple of 8 bytes
                eeprom->transfer_address &= eeprom->address_mask;
                eeprom->transfer_len = 0; // Reset for next transfer

                switch (eeprom->cmd) {
                    case EEPROM_CMD_WRITE: {
                        eeprom->transfer_data = 0;
                        eeprom->state = EEPROM_STATE_TRANSFER_DATA;
                        break;
                    };
                    case EEPROM_CMD_READ: {
                        size_t i;

                        eeprom->state = EEPROM_STATE_TRANSFER_JUNK;

                        eeprom->transfer_data = 0;
                        for (i = 0; i < 8; ++i) {
                            eeprom->transfer_data <<= 8;
                            eeprom->transfer_data |= gba->memory.backup_storage_data[eeprom->transfer_address + i];
                        }

                        break;
                    };
                }
            }
            break;
        };
        case EEPROM_STATE_TRANSFER_JUNK: break;
        case EEPROM_STATE_TRANSFER_DATA: {

            if (eeprom->cmd != EEPROM_CMD_WRITE) {
                break;
            }

            eeprom->transfer_data <<= 1;
            eeprom->transfer_data |= val;
            eeprom->transfer_len++;

            if (eeprom->transfer_len >= 64) {
                size_t i;

                eeprom->transfer_len = 0;

                for (i = 0; i < 8; ++i) {
                    gba->memory.backup_storage_data[eeprom->transfer_address + i] = (eeprom->transfer_data >> (56 - 8 * i)) & 0xFF;
                }
                gba->memory.backup_storage_dirty = true;

                eeprom->state = EEPROM_STATE_END;
            }
            break;
        };
        case EEPROM_STATE_END: {
            if (!val) {
                eeprom->state = EEPROM_STATE_READY;
            }
            break;
        }
    }
}