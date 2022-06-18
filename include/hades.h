/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
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
# ifndef __used
#  define __used            __attribute__((used))
# endif /* !__used */
# ifndef __unused
#  define __unused          __attribute__((unused))
# endif /* !__unused */
# ifndef __packed
#  define __packed          __attribute__((packed))
# endif /* !__packed */
# ifndef likely
#  define likely(x)         __builtin_expect((x), 1)
# endif /* !likely */
# ifndef unlikely
#  define unlikely(x)       __builtin_expect((x), 0)
# endif /* !unlikely */
# ifndef __noreturn
#  define __noreturn        __attribute__((noreturn))
# endif /* !__noreturn */

/*
** Calculate the number of elements of a static array.
*/
# define ARRAY_LEN(x)       (sizeof(x) / sizeof((x)[0]))

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
    [HS_GLOBAL]     = " HADES ",
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
# undef static_assert
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
                "assert(%s) failed (in %s at line %u).",    \
                #expr,                                      \
                __FILE__,                                   \
                __LINE__                                    \
            );                                              \
        }                                                   \
    }                                                       \
    while (0)

# define STRINGIFY(...)                         (#__VA_ARGS__)

/* Return the minimum between `a` and `b`. */
# ifndef min
#  define min(a, b)                             ((a) > (b) ? (b) : (a))
# endif /* !min */

/* Return the maximun between `a` and `b`. */
# ifndef max
#  define max(a, b)                             ((a) > (b) ? (a) : (b))
# endif /* !max */

/* Return the size of static array */
# define array_length(array)                    (sizeof(array) / sizeof(*(array)))

/* Get the `nth` bit of `val`. */
# define bitfield_get(val, nth)                 ((typeof(val))(bool)((val) & (1u << (nth))))

/* Return the value of the bits from `start` (inclusive) to `end` (exclusive) of `val`. */
# define bitfield_get_range(val, start, end)    ((typeof(val))(((typeof(val))((val) << (sizeof(val) * 8 - (end)))) >> (sizeof(val) * 8 - (end) + (start))))

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

/*
** Like `memset()`, but operates with `uint16_t` pointers and values.
*/
static inline
void
memset16(
    uint16_t *out,
    uint16_t value,
    size_t size
) {
    while (size) {
        *out = value;
        ++out;
        --size;
    }
}

/*
** Like `memset()`, but operates with `uint32_t` pointers and values.
*/
static inline
void
memset32(
    uint32_t *out,
    uint32_t value,
    size_t size
) {
    while (size) {
        *out = value;
        ++out;
        --size;
    }
}

/* utils.c */
char **strsplit(char *str, size_t *size);
void logln(enum modules module, char const *fmt, ...);
void panic(enum modules module, char const *fmt, ...) __attribute__((noreturn));
void unimplemented(enum modules module, char const *fmt, ...) __attribute__((noreturn));
void disable_colors(void);
void const *array_search(uint8_t const *haystack, size_t haystack_len, char const *needle, size_t needle_len);

extern bool g_verbose[HS_END];
extern bool g_verbose_global;

/*
** A set of global strings pointing to ANSI control sequences to format the terminal.
** They can also be set to the empty string if coloration is disabled.
*/
extern char const *g_reset;
extern char const *g_bold;

extern char const *g_red;
extern char const *g_green;
extern char const *g_yellow;
extern char const *g_blue;
extern char const *g_magenta;
extern char const *g_cyan;
extern char const *g_light_gray;
extern char const *g_dark_gray;
extern char const *g_light_red;
extern char const *g_light_green;
extern char const *g_light_yellow;
extern char const *g_light_blue;
extern char const *g_light_magenta;
extern char const *g_light_cyan;
extern char const *g_white;

#endif /* !HADES_H */
