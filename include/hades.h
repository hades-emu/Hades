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

# include <stdatomic.h>
# include <stdio.h>
# include <stdint.h>
# include <stdbool.h>
# include <stdarg.h>
# include <stdlib.h>
# include <pthread.h>

/*
** A useful set of macros that act like keywords that are not available
** otherwise in C11.
*/
# define inline             __inline
# define asm                __asm__
# define restrict           __restrict
# define __pure             __attribute__((pure))
# define __const            __attribute__((const))
# define __cold             __attribute__((cold))
# define __hot              __attribute__((hot))
# define __used             __attribute__((used))
# define __unused           __attribute__((unused))
# define __packed           __attribute__((packed))
# define __weak             __attribute__((weak))
# define __weakref(x)       __attribute__((weakref(x)))
# define __alias(x)         __attribute__((alias(x)))
# define __aligned(x)       __attribute__((aligned(x)))
# define __section(s)       __attribute__((section(s)))
# define __noreturn         __attribute__((noreturn))
# define likely(x)          __builtin_expect((x), 1)
# define unlikely(x)        __builtin_expect((x), 0)
# define __optimize(x)      __attribute__((optimize(x)))

/*
** Calculate the number of elements of a static array.
*/
# define ARRAY_LEN(x)       (sizeof(x) / sizeof((x)[0]))

/*
** A set of ANSI control sequences to format the terminal.
*/
# define RESET          "\e[0m"
# define BOLD           "\e[1m"

# define RED            "\e[31m"
# define GREEN          "\e[32m"
# define YELLOW         "\e[33m"
# define BLUE           "\e[34m"
# define MAGENTA        "\e[35m"
# define CYAN           "\e[36m"
# define LIGHT_GRAY     "\e[37m"
# define DARK_GRAY      "\e[90m"
# define LIGHT_RED      "\e[91m"
# define LIGHT_GREEN    "\e[92m"
# define LIGHT_YELLOW   "\e[93m"
# define LIGHT_BLUE     "\e[94m"
# define LIGHT_MAGENTA  "\e[95m"
# define LIGHT_CYAN     "\e[96m"
# define WHITE          "\e[97m"

enum modules {
    HS_GLOBAL      = 0,

    HS_ERROR,
    HS_WARNING,

    HS_CORE,
    HS_IO,
    HS_VIDEO,
    HS_DMA,
    HS_IRQ,
    HS_MEMORY,
    HS_TIMER,

    HS_DEBUG,

    HS_END,
};

static char const * const modules_str[] = {
    [HS_GLOBAL]     = "       ",
    [HS_ERROR]      = " ERROR ",
    [HS_WARNING]    = " WARN  ",
    [HS_CORE]       = " CORE  ",
    [HS_IO]         = " IO    ",
    [HS_VIDEO]      = " VIDEO ",
    [HS_DMA]        = " DMA   ",
    [HS_IRQ]        = " IRQ   ",
    [HS_MEMORY]     = " MEM   ",
    [HS_TIMER]      = " TIMER ",
    [HS_DEBUG]      = " DEBUG ",
};

/* Panic if the given constant expression evaluates to `false`. */
# define static_assert(e)                                   \
    _Static_assert(                                         \
        e,                                                  \
        "(" #e ") evaluated to false (in " __FILE__ ")"     \
    )

/* Panic if the given expression evaluates to `false` */
# define hs_assert(expr)                                    \
    do {                                                    \
        if (unlikely(!(expr))) {                            \
            panic(                                          \
                HS_ERROR,                                   \
                "assert(%s) failed (in %s at line %u).",  \
                #expr,                                      \
                __FILE__,                                   \
                __LINE__                                    \
            );                                              \
        }                                                   \
    }                                                       \
    while (0)

/* Return the size of static array */
# define array_length(array) (sizeof(array) / sizeof(*(array)))

/*
** Get the `nth` bit of `val`.
*/
# define bitfield_get(val, nth)                 ((typeof(val))(bool)((val) & (1 << (nth))))

/*
** Return the value of the bits from `start` (inclusive) to `end` (exclusive) of `val`.
*/
# define bitfield_get_range(val, start, end)    ((typeof(val))(((typeof(val))((val) << (sizeof(val) * 8 - (end)))) >> (sizeof(val) * 8 - (end) + (start))))

/*
** Set the `nth` bit of `val`.
*/
# define bitfield_set(val, nth)                 ((val) |= (1 << (nth)))

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

static inline
uint32_t
ror32(
    uint32_t value,
    uint32_t shift
) {
    return ((value >> shift) | (value << (32 - shift)));
}

/* utils.c */
char **strsplit(char *str, size_t *size);
void logln(enum modules module, char const *fmt, ...);
void panic(enum modules module, char const *fmt, ...) __attribute__((noreturn));
void unimplemented(enum modules module, char const *fmt, ...) __attribute__((noreturn));

extern atomic_bool g_stop;
extern atomic_bool g_interrupt;
extern bool g_verbose[HS_END];
extern bool g_verbose_global;

#endif /* !HADES_H */
