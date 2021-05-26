/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <ctype.h>
#include "hades.h"

#ifdef DEBUG

/*
** Append to the log the given formatted string.
*/
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

#endif

/*
** Print the given formatted string to stderr, followed by a `\n`, and then
** exit(1).
*/
__attribute__((noreturn))
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
void
unimplemented(
    enum modules module,
    char const *fmt,
    ...
) {
    va_list va;

    va_start(va, fmt);
    printf("[%s] Abort: Not Implemented: ", modules_str[module]);
    vprintf(fmt, va);
    printf("\n");
    va_end(va);

    exit(1);
}

char **
strsplit(
    char *str,
    size_t *length
) {
    size_t i;
    char **res;
    char *save;
    bool in_word;

    save = str;
    in_word = false;
    *length = 0;

    /*
    ** First we count how many words there is
    */

    while (*str) {
        if (in_word && isspace(*str)) {
            in_word = false;
        } else if (!in_word && !isspace(*str)) {
            *length += 1;
            in_word = true;
        }
        str++;
    }

    i = 0;
    in_word = false;
    str = save;

    /*
    ** Then we allocate an array big enough to hold them
    */

    res = malloc(sizeof(char *) * *length);
    hs_assert(res != NULL);

    /*
    ** And finally we fill that array with the content of `str`, modifying
    ** it to add some `\0` at word boundaries.
    */

    while (*str) {
        if (!isspace(*str)) {
            res[i] = str;
            ++i;
            while (*str) {
                if (isspace(*str)) {
                    *str = '\0';
                    str++;
                    break;
                }
                str++;
            }
        } else {
            str++;
        }
    }

    return (res);
}

