/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <stdio.h>
#include "hades.h"
#include "platform/gui/app.h"
#include "platform/gui/debugger.h"

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
    struct app *app __unused,
    size_t argc,
    struct arg const *argv
) {
    if (argc == 0) {
        g_verbose_global = !g_verbose_global;
        printf(
            "Verbosity set to %s%s%s\n",
            g_light_magenta,
            g_verbose_global ? "true" : "false",
            g_reset
        );
    } else if (argc == 1) {
        uint32_t i;

        if (debugger_check_arg_type(CMD_VERBOSE, &argv[0], ARGS_STRING)) {
            return ;
        }

        for (i = 0; verbosities[i].name; ++i) {
            if (!strcmp(verbosities[i].name, argv[0].value.s)) {
                *verbosities[i].flag ^= 1;
                printf(
                    "%s%s%s verbosity set to %s%s%s\n",
                    g_light_green,
                    verbosities[i].name,
                    g_reset,
                    g_light_magenta,
                    *verbosities[i].flag ? "true" : "false",
                    g_reset
                );
            }
        }
    } else {
        printf("Usage: %s\n", g_commands[CMD_VERBOSE].usage);
    }
}