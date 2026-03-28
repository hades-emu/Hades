/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <inttypes.h>
#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

/*
** Print the general purpose registers and the CPSR.
*/
void
debugger_cmd_registers(
    struct app *app,
    size_t argc __unused,
    struct arg const *argv __unused
) {
    size_t i;
    struct core *core;

    if (!app->debugger.is_started) {
        logln(HS_ERROR, "%s%s%s", g_red, "This command cannot be used when no game is running.", g_reset);
        return;
    }

    core = &app->emulation.gba->core;
    for (i = 0; i < 4; ++i) {
        printf(
            "%s%2s%s: %s0x%08x%s, "
            "%s%2s%s: %s0x%08x%s, "
            "%s%2s%s: %s0x%08x%s, "
            "%s%2s%s: %s0x%08x%s\n",
            g_light_green,
            registers_name[i * 4],
            g_reset,
            g_light_magenta,
            core->registers[i * 4],
            g_reset,
            g_light_green,
            registers_name[i * 4 + 1],
            g_reset,
            g_light_magenta,
            core->registers[i * 4 + 1],
            g_reset,
            g_light_green,
            registers_name[i * 4 + 2],
            g_reset,
            g_light_magenta,
            core->registers[i * 4 + 2],
            g_reset,
            g_light_green,
            registers_name[i * 4 + 3],
            g_reset,
            g_light_magenta,
            core->registers[i * 4 + 3],
            g_reset
        );
    }

    printf("\n");

    printf(
        "%sCPSR%s: %s%c%c%c%c%c%c%c%s, %s, (%s0x%08x%s) | %sCycles%s: %s%" PRIu64 "%s | %sNext fetch%s: %s%s%s",
        g_light_green,
        g_reset,
        g_light_magenta,
        core->cpsr.negative ? 'n' : '-',
        core->cpsr.zero ? 'z' : '-',
        core->cpsr.carry ? 'c' : '-',
        core->cpsr.overflow ? 'v' : '-',
        core->cpsr.irq_disable ? 'i' : '-',
        core->cpsr.fiq_disable ? 'f' : '-',
        core->cpsr.thumb ? 't' : '-',
        g_reset,
        arm_modes_name[core->cpsr.mode],
        g_light_magenta,
        core->cpsr.raw,
        g_reset,
        g_light_green,
        g_reset,
        g_light_magenta,
        app->emulation.gba->scheduler.cycles,
        g_reset,
        g_light_green,
        g_reset,
        g_light_magenta,
        core->prefetch_access_type == NON_SEQUENTIAL ? "NSEQ" : "SEQ",
        g_reset
    );

    if (core->state) {
        printf(" > %s%sHALTED%s <", g_light_red, g_bold, g_reset);
    }
    printf("\n");
}
