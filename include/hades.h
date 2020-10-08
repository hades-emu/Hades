/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#ifndef HADES_H
# define HADES_H

# include <stdio.h>
# include <stdint.h>
# include <stdbool.h>
# include <stdarg.h>
# include <stdlib.h>

# define __packed __attribute__((packed))

enum modules {
    GLOBAL      = 0,
    ERROR,
    CORE,
    DEBUG,
};

static char const * const modules_str[] = {
    [GLOBAL]    = "       ",
    [ERROR]     = " ERROR ",
    [CORE]      = " CORE  ",
    [DEBUG]     = " DEBUG ",
};

/*
** Append to the log the given formatted string.
*/
static inline
void
hs_loga(
    char const *fmt,
    ...
) {
    va_list va;

    va_start(va, fmt);
    vprintf(fmt, va);
    va_end(va);
}

/*
** Log the given formatted string, followed by a `\n`.
*/
static inline
void
hs_log(
    enum modules module,
    char const *fmt,
    ...
) {
    va_list va;

    va_start(va, fmt);
    printf("[%s] ", modules_str[module]);
    vprintf(fmt, va);
    va_end(va);
}

/*
** Log the given formatted string, followed by a `\n`.
*/
static inline
void
hs_logln(
    enum modules module,
    char const *fmt,
    ...
) {
    va_list va;

    va_start(va, fmt);
    printf("[%s] ", modules_str[module]);
    vprintf(fmt, va);
    printf("\n");
    va_end(va);
}

/*
** Print the given formatted string to stderr, followed by a `\n`, and then
** exit(1).
*/
__attribute__((noreturn))
static inline
void
panic(
    enum modules module,
    char const *fmt,
    ...
) {
    va_list va;

    va_start(va, fmt);
    printf("[%s] Abort: ", modules_str[module]);
    vprintf(fmt, va);
    printf("\n");
    va_end(va);

    exit(1);
}

/*
** Print the given formatted string to stderr, followed by a `\n`, and then
** exit(1).
*/
__attribute__((noreturn))
static inline
void
unimplemented(
    enum modules module,
    char const *fmt,
    ...
) {
    va_list va;

    va_start(va, fmt);
    printf("[%s] Abort: ", modules_str[module]);
    vprintf(fmt, va);
    printf("\n");
    va_end(va);

    exit(1);
}

/*
** Get the `nth` bit of `val`.
*/
static inline
bool
bitfield_get(
    uint32_t val,
    uint32_t nth
) {
    return (val & (1 << nth));
}

/*
** Set the `nth` bit of `val`.
*/
static inline
void
bitfield_set(
    uint32_t *val,
    uint32_t nth
) {
    *val |= (1 << nth);
}

/*
** Clear the `nth` bit of `val`.
*/
static inline
void
bitfield_clear(
    uint32_t *val,
    uint32_t nth
) {
    *val &= ~(1 << nth);
}

/*
** Set the `nth` bit of `*val` to `b`.
*/
static inline
void
bitfield_update(
    uint32_t *val,
    uint32_t nth,
    bool b
) {

    *val &= ~(1 << nth);     // Clear the bit
    *val |= (b << nth);      // Set the bit
}

/*
** Sign-extend a 24-bits value to a signed 32-bit value.
*/
static inline
int32_t
sign_extend24(
    uint32_t value
) {
     if ((value & 0x800000) != 0)
         return ((int32_t)(value | 0xFF000000));
     else
         return ((int32_t)value);
}

/*
** Safely adds `a` and `b` and store the result in `*c` if `c` is non-NULL.
** Return true if the operation overflowed.
**
** In practise, wraps `__builtin_uadd_overflow()` and
** `__builtin_uadd_overflow_p()`.
*/
static inline
bool
safe_uadd(
    uint32_t a,
    uint32_t b,
    uint32_t *c
) {
    if (c) {
        return __builtin_uadd_overflow(a, b, c);
    } else {
        return __builtin_add_overflow_p(a, b, *c);
    }
}

/*
** Safely subs `a` with `b` and store the result in `*c` if `c` is non-NULL.
** Return true if the operation overflowed.
**
** In practise, wraps `__builtin_uadd_overflow()` and
** `__builtin_uadd_overflow_p()`.
*/
static inline
bool
safe_usub(
    uint32_t a,
    uint32_t b,
    uint32_t *c
) {
    if (c) {
        return __builtin_usub_overflow(a, b, c);
    } else {
        return __builtin_sub_overflow_p(a, b, *c);
    }
}

#endif /* !HADES_H */
