/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <errno.h>
#include "hades.h"
#include "core.h"
#include "memory.h"
#include "debugger.h"

int
main(
    int argc,
    char *argv[]
) {
    if (argc == 2) {
        struct core core;
        struct memory *memory;
        struct debugger debugger;

        /* First, initialize the GBA system */

        memory = malloc(sizeof(*memory));
        hs_assert(memory != NULL);

        mem_init(memory);

        if (mem_load_rom(memory, argv[1]) < 0) {
            fprintf(stderr, "hades: can't load %s: %s", argv[1], strerror(errno));
            return (EXIT_FAILURE);
        }

        core_init(
            &core,
            memory
        );

        debugger_init(&debugger);

        /* Then enter the debugger's REPL. */

        debugger_attach(&debugger, &core);
        debugger_repl(&debugger);

        /* Finally, free all memory. */

        debugger_destroy(&debugger);

        free(memory);

        return (EXIT_SUCCESS);
    } else {
        fprintf(stderr, "Usage: %s <path_to_rom>\n", argv[0]);
        return (EXIT_FAILURE);
    }
}
