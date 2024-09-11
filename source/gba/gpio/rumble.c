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
#include "gba/event.h"

void
gpio_rumble_write(
    struct gba *gba,
    uint8_t val
) {
    gba->gpio.rumble.enabled = (bool)(val & 0b1000);
    if (gba->gpio.rumble.enabled) {
        gba_send_notification(gba, NOTIFICATION_RUMBLE);
    }
}

uint8_t
gpio_rumble_read(
    struct gba *gba
) {
    return (((uint8_t)gba->gpio.rumble.enabled) << 3);
}
