/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#ifndef ROM_H
# define ROM_H

# include <stdio.h>

struct core;

/* rom/rom.c */
void rom_load(struct core *core, FILE *file);

#endif /* !ROM_H */