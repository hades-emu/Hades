/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <ctype.h>
#include "hades.h"

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
