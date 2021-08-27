/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef COMPAT_H
# define COMPAT_H

# include "hades.h"

#if defined (_WIN32) && !defined (__CYGWIN__)
# define INCLUDE_SYS_IO
# include <io.h>
# include <fileapi.h>
# include <stdio.h>
# include <sysinfoapi.h>

# define hs_isatty(x)           _isatty(x)
# define hs_mkdir(path)         CreateDirectoryA((path), NULL)
# define hs_tick_count()        ((uint64_t)GetTickCount())
#else
# include <sys/stat.h>
# include <unistd.h>
# include <time.h>

# define hs_isatty(x)           isatty(x)
# define hs_mkdir(path)         mkdir((path), 0755);

static
inline
uint64_t
hs_tick_count(void)
{
    struct timespec ts;

    hs_assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

#endif

#endif /* !COMPAT_H */