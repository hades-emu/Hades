/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <time.h>
#include "gba/gba.h"
#include "gba/gpio.h"

static inline
bool
gpio_rtc_write_sio(
    struct gba *gba
) {
    struct rtc *rtc;

    rtc = &gba->gpio.rtc;

    // Progress the transfer by 1 bit
    rtc->sio = bitfield_get(rtc->data, 0);
    rtc->data >>= 1;
    ++rtc->data_count;

    return (rtc->data_count >= rtc->data_len);
}

static inline
bool
gpio_rtc_read_sio(
    struct gba *gba
) {
    struct rtc *rtc;

    rtc = &gba->gpio.rtc;

    // Progress the transfer by 1 bit
    rtc->data &= ~(1 << rtc->data_count);           // Clear the nth bit (just in case)
    rtc->data |= rtc->sio << rtc->data_count;       // Set the nth bit to the value contained in SIO
    ++rtc->data_count;

    return (rtc->data_count >= rtc->data_len);
}

static inline
uint8_t
gpio_rtc_to_bcd(
    uint8_t val
) {
    return ((val / 10 % 10) << 4 | (val % 10));
}

static inline
uint64_t
gpio_rtc_get_date_time(
    struct gba const *gba
) {
    time_t t;
    struct tm *tm;
    uint64_t res;
    bool use_24h;

    t = time(NULL);
    tm = localtime(&t);
    use_24h = gba->gpio.rtc.control.mode_24h;

    res = 0;
    res = (res << 8) | gpio_rtc_to_bcd(tm->tm_sec);                             // Seconds
    res = (res << 8) | gpio_rtc_to_bcd(tm->tm_min);                             // Minute
    res = (res << 8) | gpio_rtc_to_bcd(tm->tm_hour % (use_24h ? 24 : 12));      // Hour
    res = (res << 8) | gpio_rtc_to_bcd(tm->tm_wday);                            // Day of week
    res = (res << 8) | gpio_rtc_to_bcd(tm->tm_mday);                            // Day of the month
    res = (res << 8) | gpio_rtc_to_bcd(tm->tm_mon + 1);                         // Month
    res = (res << 8) | gpio_rtc_to_bcd(tm->tm_year % 100);                      // Year
    return (res);
}

static inline
uint64_t
gpio_rtc_get_time(
    struct gba const *gba
) {
    return ((gpio_rtc_get_date_time(gba) >> 32) & 0xFFFFFF);
}

static inline
void
gpio_rtc_reset(
    struct rtc *rtc
) {
    rtc->state = RTC_COMMAND;
    rtc->data_len = 8;
    rtc->data = 0;
    rtc->data_count = 0;
}

static inline
void
gpio_rtc_prepare_transfer(
    struct rtc *rtc,
    enum rtc_states state,
    enum rtc_registers reg
) {
    rtc->state = state;
    rtc->data = 0;
    rtc->data_count = 0;
    rtc->active_register = reg;
    switch (reg) {
        case RTC_REG_CONTROL:   rtc->data_len = 8; break;
        case RTC_REG_DATE_TIME: rtc->data_len = 8 * 7; break;
        case RTC_REG_TIME:      rtc->data_len = 8 * 3; break;
        default:                rtc->data_len = 8;
    }
}

void
gpio_rtc_write(
    struct gba *gba,
    uint8_t val
) {
    struct rtc *rtc;
    bool old_sck;
    bool old_cs;

    rtc = &gba->gpio.rtc;
    old_sck = rtc->sck;
    old_cs = rtc->cs;

    rtc->sck = bitfield_get(val, 0);
    rtc->sio = bitfield_get(val, 1);
    rtc->cs  = bitfield_get(val, 2);

    if (!old_cs && rtc->cs) {
        gpio_rtc_reset(rtc);
    }

    // Only continue if CS is set and SCK is rising
    if (!(rtc->cs && !old_sck && rtc->sck)) {
        return;
    }

    switch (rtc->state) {
        case RTC_COMMAND: {
            if (gpio_rtc_read_sio(gba)) { // Transfer completed
                uint8_t data;

                data = rtc->data;
                rtc->data = 0;

                /*
                ** If data doesn't match a specific pattern then swap all bits
                **   - https://graphics.stanford.edu/~seander/bithacks.html
                */
                if ((data >> 4) != 6) {
                    data = ((data * 0x0802LU & 0x22110LU) | (data * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
                }

                // Do stuff depending on targeted register
                switch (data & 0xF) {
                    case ((RTC_REG_RESET << 1) | 0): {  // Write to Reset
                        rtc->control.raw = 0;
                        gpio_rtc_reset(rtc);
                        break;
                    };
                    case ((RTC_REG_CONTROL << 1) | 0): { // Write to Control
                        gpio_rtc_prepare_transfer(rtc, RTC_REG_RECV, RTC_REG_CONTROL);
                        break;
                    };
                    case ((RTC_REG_CONTROL << 1) | 1): {  // Read to Control
                        gpio_rtc_prepare_transfer(rtc, RTC_REG_SEND, RTC_REG_CONTROL);
                        rtc->data = rtc->control.raw & 0b01001010;
                        break;
                    };
                    case ((RTC_REG_DATE_TIME << 1) | 0): {  // Write to Date/Time
                        gpio_rtc_prepare_transfer(rtc, RTC_REG_RECV, RTC_REG_DATE_TIME);
                        break;
                    };
                    case ((RTC_REG_DATE_TIME << 1) | 1): {  // Read to Date/Time
                        gpio_rtc_prepare_transfer(rtc, RTC_REG_SEND, RTC_REG_DATE_TIME);
                        rtc->data = gpio_rtc_get_date_time(gba);
                        break;
                    };
                    case ((RTC_REG_TIME << 1) | 0): {  // Write to Time
                        gpio_rtc_prepare_transfer(rtc, RTC_REG_RECV, RTC_REG_TIME);
                        break;
                    };
                    case ((RTC_REG_TIME << 1) | 1): {  // Read to Time
                        gpio_rtc_prepare_transfer(rtc, RTC_REG_SEND, RTC_REG_TIME);
                        rtc->data = gpio_rtc_get_time(gba);
                        break;
                    };
                }
            }
            break;
        };
        case RTC_REG_SEND: {
            if (gpio_rtc_write_sio(gba)) {
                // Back to waiting for a new command
                gpio_rtc_reset(rtc);
            }
            break;
        };
        case RTC_REG_RECV: {
            if (gpio_rtc_read_sio(gba)) {
                // The only register we support write to is the control register.
                if (rtc->active_register == RTC_REG_CONTROL) {
                    rtc->control.raw = rtc->data;
                    rtc->control.poweroff = 0;
                }

                // Back to waiting for a new command
                gpio_rtc_reset(rtc);
            }
            break;
        };
    }
}

uint8_t
gpio_rtc_read(
    struct gba const *gba
) {
    return (gba->gpio.rtc.sio << 1);
}
