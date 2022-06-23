/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#ifndef UTILS_FS_H
# define UTILS_FS_H

# include <string.h>
# include "hades.h"

# if defined (_WIN32) && !defined (__CYGWIN__)
#  include <io.h>
#  include <fileapi.h>
#  include <stdio.h>

#  define hs_isatty(x)          false
#  define hs_mkdir(path)        CreateDirectoryA((path), NULL)

static inline
wchar_t *
hs_convert_to_wchar(
    char const *str
) {
    wchar_t *wstr;
    size_t len;
    size_t new_len;
    errno_t err;

    len = strlen(str) + 1;
    wstr = malloc(sizeof(wchar_t) * len);
    hs_assert(wstr);

    err = mbstowcs_s(
        &new_len,
        wstr,
        len,
        str,
        _TRUNCATE
    );

    logln(HS_GLOBAL, "ERR=%i, LEN=%zu, NEWLEN=%zu\n", err, len, new_len);

    if (err) {
        free(wstr);
        return (NULL);
    }
    return (wstr);
}

static inline
FILE *
hs_fopen(
    char const *path,
    char const *mode
) {
    FILE *file;
    wchar_t *wpath;
    wchar_t *wmode;

    wpath = hs_convert_to_wchar(path);
    wmode = hs_convert_to_wchar(mode);

    logln(HS_GLOBAL, "PATH=%ls, MODE=%ls\n", wpath, wmode);

    if (!wpath || !wmode) {
        file = NULL;
        goto end;
        return (NULL);
    }

    file = _wfopen(wpath, wmode);
end:
    free(wpath);
    free(wmode);
    return (file);
}

static inline
char const *
hs_basename(
    char const *path
) {
    char const *base;

    base = strrchr(path, '\\');
    return (base ? base + 1 : path);
}

# else
#  include <sys/stat.h>
#  include <unistd.h>

#  define hs_isatty(x)           isatty(x)
#  define hs_mkdir(path)         mkdir((path), 0755);
#  define hs_fopen(path, mode)   fopen((char const *)(path), (mode))

static inline
char const *
hs_basename(
    char const *path
) {
    char const *base;

    base = strrchr(path, '/');
    return (base ? base + 1 : path);
}

# endif

#endif /* UTILS_FS_H */