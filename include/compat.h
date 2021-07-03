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

#if defined (_WIN32) && !defined (__CYGWIN__)
# define INCLUDE_SYS_IO
# include <io.h>
# include <fileapi.h>
# include <stdio.h>

# define hs_isatty(x)           _isatty(x)
# define hs_mkdir(path)         CreateDirectoryA((path), NULL)
#else
# include <sys/stat.h>
# include <unistd.h>

# define hs_isatty(x)           isatty(x)
# define hs_mkdir(path)         mkdir(path, 0755);
#endif

#endif /* !COMPAT_H */