/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#ifndef GBA_DB_H
# define GBA_DB_H

# include "gba/memory.h"

# define FLAGS_NONE 0x0
# define FLAGS_RTC  0x1

struct game_entry {
    char *code;
    enum backup_storage_types storage;
    uint64_t flags;
    char *title;
};

/* gba/db.c */
void db_lookup_game(struct gba *gba);

#endif /* !GBA_DB_H */
