/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba/gba.h"

/*
** Handler for THUMB software breakpoints.
*/
void
core_thumb_brk(
    struct gba *gba,
    uint16_t op
) {
    struct core *core;
    uint32_t addr;
    uint16_t insn;

    core = &gba->core;

    addr = core->pc - 4;
    insn = *(uint16_t *)(gba->memory.unpatched_rom + (addr & gba->memory.rom_mask));

    dbgln(HS_CORE, "Breakpoint instruction hit.");

    cheat_process_hooks_at_addr(gba, addr);

#ifdef WITH_DEBUGGER
    debugger_eval_sw_breakpoints(gba, addr);
#endif

    core_execute_thumb_opcode(gba, insn);
}
