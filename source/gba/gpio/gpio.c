/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/gpio.h"

uint8_t
gpio_read_u8(
    struct gba *gba,
    uint32_t addr
) {
    switch (addr) {
        case GPIO_REG_CTRL: {
            return (gba->gpio.readable);
        };
        case GPIO_REG_DATA: {
            uint8_t val;

            if (gba->gpio.rtc.enabled) {
                val = gpio_rtc_read(gba);
            } else {
                val = 0;
            }
            return (val);
        };
        case GPIO_REG_DIRECTION: {
            return (0); // FIXME
        };
    }
    return (0);
}

void
gpio_write_u8(
    struct gba *gba,
    uint32_t addr,
    uint8_t val
) {
    switch (addr) {
        case GPIO_REG_CTRL: {
            gba->gpio.readable = val & 0b1;
            break;
        };
        case GPIO_REG_DATA: {
            if (gba->gpio.rtc.enabled) {
                gpio_rtc_write(gba, val);
            }
            break;
        };
        case GPIO_REG_DIRECTION: {
            break;
        };
    }
}
