/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include "hades.h"
#include "app.h"
#include "dbg/dbg.h"
#include "compat.h"

/*
** Dump the registers' content, a disassembly of instructions around the PC
** and the content of the stack.
*/
void
debugger_dump_context(
    struct app *app,
    bool force
) {
    if (!force && !hs_isatty(STDIN_FILENO)) {
        return ;
    }

    printf("---------------------------------Registers----------------------------------\n");
    debugger_cmd_registers(
        app,
        0,
        NULL
    );
    printf("------------------------------------Code------------------------------------\n");
    debugger_cmd_disas(
        app,
        0,
        NULL
    );
    printf("-----------------------------------Stack------------------------------------\n");
    debugger_cmd_print_u8(
        app,
        app->emulation.gba->core.sp,
        3 * 16,
        16
    );
    printf("----------------------------------------------------------------------------\n");
}

void
debugger_dump_context_compact_header(void)
{
    size_t i;

    printf("  %sCycle Counter%s  ", g_light_green, g_reset);

    for (i = 0; i < 16; ++i) {
        printf(
            "   %s%s%s    ",
            g_light_green,
            registers_name[i],
            g_reset
        );
    }

    printf("   %sCPSR%s", g_light_green, g_reset);
    printf("\n");
}

/*
** Print a shorter, more compact version of `debugger_dump_context()` (regs only).
*/
void
debugger_dump_context_compact(
    struct app *app
) {
    struct core *core;
    size_t i;
    bool thumb;
    size_t op_len;

    core = &app->emulation.gba->core;
    thumb = core->cpsr.thumb;
    op_len = thumb ? 2 : 4;

    printf(
        "%016" PRIu64 " ",
        core->cycles
    );

    for (i = 0; i < 16; ++i) {
        printf(
            "%08x ",
            core->registers[i]
        );
    }

    printf(
        "%c%c%c%c%c%c%c/%s   ",
        core->cpsr.negative ? 'n' : '-',
        core->cpsr.zero ? 'z' : '-',
        core->cpsr.carry ? 'c' : '-',
        core->cpsr.overflow ? 'v' : '-',
        core->cpsr.irq_disable ? 'i' : '-',
        core->cpsr.fiq_disable ? 'f' : '-',
        core->cpsr.thumb ? 't' : '-',
        arm_modes_name[core->cpsr.mode]
    );

    debugger_cmd_disas_at(app, core->pc - op_len * 2, thumb);
    printf("\n");
}

void
debugger_cmd_context(
    struct app *app,
    size_t argc __unused,
    struct arg const *argv __unused
) {
    debugger_dump_context(app, true);
}

void
debugger_cmd_context_compact(
    struct app *app,
    size_t argc __unused,
    struct arg const *argv __unused
) {
    debugger_dump_context_compact(app);
    debugger_dump_context_compact_header();
}