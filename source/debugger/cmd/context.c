/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "debugger.h"
#include "hades.h"

void
debugger_dump_context(
    struct debugger *debugger
) {
    printf("---------------------------------Registers----------------------------------\n");
    debugger_cmd_registers(
        debugger,
        1,
        ((char const * const[]){"registers"})
    );
    printf("------------------------------------Code------------------------------------\n");
    debugger_cmd_disas(
        debugger,
        1,
        ((char const * const[]){"disas"})
    );
    if (debugger->core->r13 > 5 * 16) {
        printf("-----------------------------------Stack------------------------------------\n");
        debugger_cmd_print_u8(
            debugger->core,
            debugger->core->r13 - 5 * 16,
            5 * 16,
            16
        );
    }
    printf("----------------------------------------------------------------------------\n");
}

void
debugger_cmd_context(
    struct debugger *debugger,
    size_t argc __unused,
    char const * const *argv __unused
) {
    debugger_dump_context(debugger);
}