/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <ctype.h>
#include "hades.h"

/*
** A global variable used to indicate the verbosity of all the different log levels.
*/
bool g_verbose_global = true;
bool g_verbose[HS_END] = {
    [HS_GLOBAL] = true,
    [HS_WARNING] = true,
    [HS_ERROR] = true,
};

/*
** A set of global strings pointing to ANSI control sequences to format the terminal.
** They can also be set to the empty string if coloration is disabled.
*/
char const *g_reset          = "\e[0m";
char const *g_bold           = "\e[1m";

char const *g_red            = "\e[31m";
char const *g_green          = "\e[32m";
char const *g_yellow         = "\e[33m";
char const *g_blue           = "\e[34m";
char const *g_magenta        = "\e[35m";
char const *g_cyan           = "\e[36m";
char const *g_light_gray     = "\e[37m";
char const *g_dark_gray      = "\e[90m";
char const *g_light_red      = "\e[91m";
char const *g_light_green    = "\e[92m";
char const *g_light_yellow   = "\e[93m";
char const *g_light_blue     = "\e[94m";
char const *g_light_magenta  = "\e[95m";
char const *g_light_cyan     = "\e[96m";
char const *g_white          = "\e[97m";

void
disable_colors(void)
{
    g_reset          = "";
    g_bold           = "";

    g_red            = "";
    g_green          = "";
    g_yellow         = "";
    g_blue           = "";
    g_magenta        = "";
    g_cyan           = "";
    g_light_gray     = "";
    g_dark_gray      = "";
    g_light_red      = "";
    g_light_green    = "";
    g_light_yellow   = "";
    g_light_blue     = "";
    g_light_magenta  = "";
    g_light_cyan     = "";
    g_white          = "";
}

/*
** Log the given formatted string, followed by a `\n`.
*/
void
logln(
    enum modules module,
    char const *fmt,
    ...
) {
    va_list va;

    if (module == HS_GLOBAL || (g_verbose_global && g_verbose[module])) {
        va_start(va, fmt);
        printf("[%s] ", modules_str[module]);
        vprintf(fmt, va);
        printf("\n");
        va_end(va);
    }
}

/*
** Print the given formatted string to stderr and finally exit(1).
*/
__noreturn
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
__noreturn
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

void const *
array_search(
    uint8_t const *haystack,
    size_t haystack_len,
    char const *needle,
    size_t needle_len
) {
    uint8_t const *tmp;

    tmp = haystack;
    while (haystack_len >= needle_len) {
        if (!memcmp(tmp, needle, needle_len)) {
            return (tmp);
        }
        ++tmp;
        --haystack_len;
    }
    return (NULL);
}