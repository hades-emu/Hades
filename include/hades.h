/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#pragma once

#define _GNU_SOURCE

#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h>
#include "log.h"

/*
** A useful set of macros that act like keywords that are not available
** otherwise in C11.
*/
#ifndef __used
# define __used             __attribute__((used))
#endif /* !__used */
#ifndef __unused
# define __unused           __attribute__((unused))
#endif /* !__unused */
#ifndef __packed
# define __packed           __attribute__((packed))
#endif /* !__packed */
#ifndef likely
# define likely(x)          __builtin_expect((x), 1)
#endif /* !likely */
#ifndef unlikely
# define unlikely(x)        __builtin_expect((x), 0)
#endif /* !unlikely */
#ifndef __noreturn
# define __noreturn         __attribute__((noreturn))
#endif /* !__noreturn */
#ifndef __unreachable
# define __unreachable      __builtin_unreachable()
#endif /* !__unreachable */

/* Panic if the given constant expression evaluates to `false`. */
#undef static_assert
#define static_assert(e)                                    \
    _Static_assert(                                         \
        e,                                                  \
        "(" #e ") evaluated to false (in " __FILE__ ")"     \
    )

/* Panic if the given expression evaluates to `false` */
#define hs_assert(expr)                                     \
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
    } while (0)

/* Return an allocated string according to the given format */
#define hs_format(fmt, ...)                                 \
    ({                                                      \
        char *__tmp;                                        \
                                                            \
        hs_assert(-1 != asprintf(&__tmp, fmt, ##__VA_ARGS__));\
        __tmp;                                              \
    })

/* ✨ Variadic macro magic ✨ */
#define XSTR(...)                #__VA_ARGS__
#define STR(...)               XSTR(__VA_ARGS__)
#define XCONCAT(a, b)           a ## b
#define CONCAT(a, b)            XCONCAT(a, b)
#define NTH(_0, _1, _2, _3, _4, _5, N, ...) N
#define NARG(...)               NTH(, ##__VA_ARGS__, 5, 4, 3, 2, 1, 0)

/* Return the minimum between `a` and `b`. */
#ifndef min
#define min(a, b)                               ((a) > (b) ? (b) : (a))
#endif /* !min */

/* Return the maximun between `a` and `b`. */
#ifndef max
#define max(a, b)                               ((a) > (b) ? (a) : (b))
#endif /* !max */

/* Return the size of static array */
#define array_length(array)                     (sizeof(array) / sizeof(*(array)))

/* Get the `nth` bit of `val`. */
#define bitfield_get(val, nth)                  ((typeof(val))(bool)((val) & (1u << (nth))))

/* Return the value of the bits from `start` (inclusive) to `end` (exclusive) of `val`. */
#define bitfield_get_range(val, start, end)     ((typeof(val))(((typeof(val))((val) << (sizeof(val) * 8 - (end)))) >> (sizeof(val) * 8 - (end) + (start))))

/* Align `x` to the given power of two. */
#define align_on(x, y)                          ((x) & ~((y) - 1))

/* Align `x` to the size of T */
#define align(T, x)                             ((typeof(x))(align_on((x), sizeof(T))))
