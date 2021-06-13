/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <unistd.h>
#include "hades.h"
#include "debugger.h"
#include "gba.h"

void
debugger_dump_context(
    struct gba *gba,
    bool force
) {
    if (!force && !isatty(STDIN_FILENO)) {
        return ;
    }

    printf("---------------------------------Registers----------------------------------\n");
    debugger_cmd_registers(
        gba,
        1,
        ((char const * const[]){"registers"})
    );
    printf("------------------------------------Code------------------------------------\n");
    debugger_cmd_disas(
        gba,
        1,
        ((char const * const[]){"disas"})
    );
    printf("-----------------------------------Stack------------------------------------\n");
    debugger_cmd_print_u8(
        gba,
        gba->core.sp,
        5 * 16,
        16
    );
    printf("----------------------------------------------------------------------------\n");
}

void
debugger_cmd_context(
    struct gba *gba,
    size_t argc __unused,
    char const * const *argv __unused
) {
    debugger_dump_context(gba, true);
}