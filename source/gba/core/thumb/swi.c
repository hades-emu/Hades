/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba/gba.h"

void
core_thumb_swi(
    struct gba *gba,
    uint16_t op
) {
    core_interrupt(gba, VEC_SVC, MODE_SVC);
}