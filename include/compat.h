/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#ifndef UTILS_COMMON_H
# define UTILS_COMMON_H

# include <string.h>
# include "hades.h"

# if defined (_WIN32) && !defined (__CYGWIN__)
#  include <io.h>
#  include <fileapi.h>
#  include <stdio.h>
#  include <stringapiset.h>
#  include <windows.h>
#  include <sysinfoapi.h>
#  include <synchapi.h>

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

    if (!wpath || !wmode) {
        file = NULL;
        goto end;
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

static inline
bool
hs_fexists(
    char const *path
) {
    wchar_t *wpath;
    bool out;

    wpath = hs_convert_to_wchar(path);
    if (!wpath) {
        return (false);
    }

    out = _waccess(wpath, 0) == 0;

    free(wpath);
    return (out);
}

static inline
char *
hs_fmtime(
    char *path
) {
    wchar_t *wpath;
    struct _stat stbuf;
    struct tm *tm;
    char *out;

    out = NULL;
    wpath = hs_convert_to_wchar(path);
    if (!wpath) {
        goto end;
    }

    if (_wstat(wpath, &stbuf)) {
        goto end;
    }

    out = malloc(sizeof(char) * 128);
    hs_assert(out);

    tm = localtime(&stbuf.st_mtime);
    strftime(out, 128, "%c", tm);

end:
    free(wpath);
    return (out);
}

static
inline
void
hs_usleep(
    uint64_t x
) {
    HANDLE timer;
    LARGE_INTEGER ft;

    ft.QuadPart = -(10 * x);

    timer = CreateWaitableTimer(NULL, TRUE, NULL);
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
    WaitForSingleObject(timer, INFINITE);
    CloseHandle(timer);
}

static
inline
uint64_t
hs_tick_count(void)
{
    FILETIME ts;
    uint64_t time;

    GetSystemTimeAsFileTime(&ts);
    time = (uint64_t)ts.dwHighDateTime << 32u | ts.dwLowDateTime;
    time /= 10;
    return (time);
}

# else
#  include <sys/stat.h>
#  include <unistd.h>
#  include <time.h>

#  define hs_isatty(x)          isatty(x)
#  define hs_mkdir(path)        mkdir((path), 0755);
#  define hs_fopen(path, mode)  fopen((char const *)(path), (mode))
#  define hs_usleep(x)          usleep(x)
#  define hs_fexists(path)      (access((path), F_OK) == 0)

static inline
char const *
hs_basename(
    char const *path
) {
    char const *base;

    base = strrchr(path, '/');
    return (base ? base + 1 : path);
}

static
inline
uint64_t
hs_tick_count(void)
{
    struct timespec ts;

    hs_assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
}

static inline
char *
hs_fmtime(
    char *path
) {
    struct stat stbuf;
    struct tm *tm;
    char *out;

    if (stat(path, &stbuf)) {
        return (NULL);
    }

    out = malloc(sizeof(char) * 128);
    hs_assert(out);

    tm = localtime(&stbuf.st_mtime);
    strftime(out, 128, "%c", tm);
    return (out);
}

# endif

#endif /* !UTILS_COMMON_H */