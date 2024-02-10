/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#pragma once

#include "hades.h"

/*
** Sign-extend a 8-bits value to a signed 32-bit value.
*/
static inline
int32_t
sign_extend8(
    uint32_t value
) {
    if ((value & 0x80) != 0) {
        return ((int32_t)(value | 0xFFFFFF00));
    } else {
        return ((int32_t)value);
    }
}

/*
** Sign-extend a 9-bits value to a signed 32-bit value.
*/
static inline
int32_t
sign_extend9(
    uint32_t value
) {
    if ((value & 0x100) != 0) {
        return ((int32_t)(value | 0xFFFFFF00));
    } else {
        return ((int32_t)value);
    }
}

/*
** Sign-extend a 11-bits value to a signed 32-bit value.
*/
static inline
int32_t
sign_extend11(
    uint32_t value
) {
    if ((value & 0x400) != 0) {
        return ((int32_t)(value | 0xFFFFF800));
    } else {
        return ((int32_t)value);
    }
}

/*
** Sign-extend a 12-bits value to a signed 32-bit value.
*/
static inline
int32_t
sign_extend12(
    uint32_t value
) {
    if ((value & 0x800) != 0) {
        return ((int32_t)(value | 0xFFFFF000));
    } else {
        return ((int32_t)value);
    }
}

/*
** Sign-extend a 24-bits value to a signed 32-bit value.
*/
static inline
int32_t
sign_extend24(
    uint32_t value
) {
    if ((value & 0x800000) != 0) {
        return ((int32_t)(value | 0xFF000000));
    } else {
        return ((int32_t)value);
    }
}

/*
** Sign-extend a 28-bits value to a signed 32-bit value.
*/
static inline
int32_t
sign_extend28(
    uint32_t value
) {
    if ((value & 0x08000000) != 0) {
        return ((int32_t)(value | 0xF0000000));
    } else {
        return ((int32_t)value);
    }
}

/*
** Return the value of the carry bit when performing `a + b + c`.
*/
static inline
bool
uadd32(
    uint32_t a,
    uint32_t b,
    uint32_t c
) {
    uint64_t r;

    r = (uint64_t)a + (uint64_t)b + (uint64_t)c;
    return (r > UINT32_MAX);
}

/*
** Return the value of the overflow bit when performing `a + b + c`.
*/
static inline
bool
iadd32(
    int32_t a,
    int32_t b,
    int32_t c
) {
    int64_t r;

    r = (int64_t)a + (int64_t)b + (int64_t)c;
    return ((r < INT32_MIN) | (r > INT32_MAX));
}

/*
** Return the value of the borrow bit when performing `a - b - c`.
*/
static inline
bool
usub32(
    uint32_t a,
    uint32_t b,
    uint32_t c
) {
    uint64_t r;

    r = (uint64_t)a - (uint64_t)b -(uint64_t)c;
    return (r <= UINT32_MAX);
}

/*
** Return the value of the overflow bit when performing `a - b - c`.
*/
static inline
bool
isub32(
    int32_t a,
    int32_t b,
    int32_t c
) {
    int64_t r;

    r = (int64_t)a - (int64_t)b - (int64_t)c;
    return ((r < INT32_MIN) | (r > INT32_MAX));
}

/*
** Return the value of value after being wrapped by `shift` amount.
*/
static inline
uint32_t
ror32(
    uint32_t value,
    uint32_t shift
) {
    if (shift) {
        return ((value >> shift) | (value << (32 - shift)));
    } else {
        return (value);
    }
}
