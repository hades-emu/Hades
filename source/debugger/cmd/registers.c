/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "debugger.h"
#include "gba.h"

/*
** Print the general purpose registers and the CPSR.
*/
void
debugger_cmd_registers(
    struct gba *gba,
    size_t argc __unused,
    char const * const *argv __unused
) {
    size_t i;
    struct core *core;

    core = &gba->core;
    for (i = 0; i < 4; ++i) {
        printf(
            LIGHT_GREEN "%2s" RESET ": " LIGHT_MAGENTA "0x%08x" RESET ", "
            LIGHT_GREEN "%2s" RESET ": " LIGHT_MAGENTA "0x%08x" RESET ", "
            LIGHT_GREEN "%2s" RESET ": " LIGHT_MAGENTA "0x%08x" RESET ", "
            LIGHT_GREEN "%2s" RESET ": " LIGHT_MAGENTA "0x%08x" RESET "\n",
            registers_name[i * 4],
            core->registers[i * 4],
            registers_name[i * 4 + 1],
            core->registers[i * 4 + 1],
            registers_name[i * 4 + 2],
            core->registers[i * 4 + 2],
            registers_name[i * 4 + 3],
            core->registers[i * 4 + 3]
        );
    }

    printf("\n");

    printf(
        LIGHT_GREEN "CPSR" RESET ": " LIGHT_MAGENTA "%c%c%c%c%c%c%c" RESET ", %s, (" LIGHT_MAGENTA "0x%08x" RESET ") | " LIGHT_GREEN "Cycles" RESET ": " LIGHT_MAGENTA "%#lx" RESET,
        core->cpsr.negative ? 'n' : '-',
        core->cpsr.zero ? 'z' : '-',
        core->cpsr.carry ? 'c' : '-',
        core->cpsr.overflow ? 'v' : '-',
        core->cpsr.irq_disable ? 'i' : '-',
        core->cpsr.fiq_disable ? 'f' : '-',
        core->cpsr.thumb ? 't' : '-',
        arm_modes_name[core->cpsr.mode],
        core->cpsr.raw,
        gba->scheduler.cycles
    );

    if (core->halt) {
        printf(" > " LIGHT_RED BOLD "HALTED" RESET " <");
    }
    printf("\n");
}
