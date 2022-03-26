/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#ifndef COMPAT_TIME_H
# define COMPAT_TIME_H

# include "hades.h"

# if defined (_WIN32) && !defined (__CYGWIN__)

#  include <windows.h>
#  include <sysinfoapi.h>
#  include <synchapi.h>

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
#  include <unistd.h>
#  include <time.h>

#  define hs_usleep(x)           usleep(x)

static
inline
uint64_t
hs_tick_count(void)
{
    struct timespec ts;

    hs_assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
}

#endif

#endif /* !COMPAT_TIME_H */