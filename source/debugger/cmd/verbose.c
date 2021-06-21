/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba.h"
#include "debugger.h"
#include "hades.h"

struct verbosity_arg {
    char const *name;
    bool *flag;
};

struct verbosity_arg verbosities[] = {
    { "io",         g_verbose + HS_IO       },
    { "global",     g_verbose + HS_GLOBAL   },
    { "err",        g_verbose + HS_ERROR    },
    { "warn",       g_verbose + HS_WARNING  },
    { "core",       g_verbose + HS_CORE     },
    { "video",      g_verbose + HS_VIDEO    },
    { "dma",        g_verbose + HS_DMA      },
    { "irq",        g_verbose + HS_IRQ      },
    { "mem",        g_verbose + HS_MEMORY   },
    { "timer",      g_verbose + HS_TIMER    },
    { "debug",      g_verbose + HS_DEBUG    },
    { NULL,         NULL                    },
};

void
debugger_cmd_verbose(
    struct gba *gba,
    size_t argc,
    char const * const *argv
) {
    if (argc == 1) {
        g_verbose_global = !g_verbose_global;
        printf("Verbosity set to " LIGHT_MAGENTA "%s" RESET "\n", g_verbose_global ? "true" : "false");
    } else if (argc == 2) {
        uint i;

        for (i = 0; verbosities[i].name; ++i) {
            if (!strcmp(verbosities[i].name, argv[1])) {
                *verbosities[i].flag ^= 1;
                printf(
                    LIGHT_GREEN "%s" RESET " verbosity set to " LIGHT_MAGENTA "%s" RESET "\n",
                    verbosities[i].name,
                    *verbosities[i].flag ? "true" : "false"
                );
            }
        }
    } else {
        printf("Usage: %s\n", g_commands[CMD_STEP].usage);
    }
}