/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

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

            switch (gba->gpio.device) {
                case GPIO_RTC: {
                    val = gpio_rtc_read(gba);
                    break;
                };
                case GPIO_RUMBLE: {
                    val = gpio_rumble_read(gba);
                    break;
                };
                default: {
                    val = 0;
                    break;
                }
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
            switch (gba->gpio.device) {
                case GPIO_RTC: {
                    gpio_rtc_write(gba, val);
                    break;
                }
                case GPIO_RUMBLE: {
                    gpio_rumble_write(gba, val);
                    break;
                }
                default: break;
            }
        };
        case GPIO_REG_DIRECTION: {
            break;
        };
    }
}
