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
#  include <stringapiset.h>

#  define hs_isatty(x)          false
#  define hs_mkdir(path)        CreateDirectoryA((path), NULL)

static inline
wchar_t *
hs_convert_to_wchar(
    char const *str
) {
    wchar_t *wstr;
    int len;
    int wlen;
    errno_t err;

    len = strlen(str);
    wlen = MultiByteToWideChar(CP_UTF8, 0, str, len, 0, 0);

    wstr = malloc(sizeof(wchar_t) * (wlen + 1));
    hs_assert(wstr);

    MultiByteToWideChar(CP_UTF8, 0, str, len, wstr, wlen);
    wstr[wlen] = '\0';

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

    wprintf(L"1:PATH=%ls, MODE=%ls\n", wpath, wmode);
    wprintf(L"2:PATH=%S, MODE=%S\n", wpath, wmode);

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

#  define hs_isatty(x)          isatty(x)
#  define hs_mkdir(path)        mkdir((path), 0755);
#  define hs_fopen(path, mode)  fopen((char const *)(path), (mode))

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