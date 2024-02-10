/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <capstone/arm.h>
#include <capstone/capstone.h>
#include <string.h>
#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

static
size_t
find_biggest_mnenmonic(
    cs_insn *insn,
    size_t count
) {
    size_t i;
    size_t best;

    i = 0;
    best = 0;
    while (i < count) {
        size_t size;

        size = strlen(insn[i].mnemonic);
        if (size > best) {
            best = size;
        }
        ++i;
    }
    return (best);
}

static
size_t
try_disas(
    csh handle,
    cs_insn **insn_ptr,
    struct memory const *memory,
    uint32_t addr,
    bool thumb,
    size_t count
) {
    size_t op_len;

    op_len = thumb ? 2 : 4;

    // TODO FIXME use mem_read instead of this ugly shit.
    switch (addr) {
        case BIOS_START ... BIOS_END:
            if (addr + count * op_len >= BIOS_END) {
                return (0);
            }
            return (cs_disasm(
                handle,
                (uint8_t *)memory->bios + (addr & BIOS_MASK),
                op_len * count,
                addr,
                count,
                insn_ptr
            ));
        case EWRAM_START ... EWRAM_END:
            if (addr + count * op_len >= EWRAM_END) {
                return (0);
            }
            return (cs_disasm(
                handle,
                (uint8_t *)memory->ewram + (addr & EWRAM_MASK),
                op_len * count,
                addr,
                count,
                insn_ptr
            ));
        case IWRAM_START ... IWRAM_END:
            if (addr + count * op_len >= IWRAM_END) {
                return (0);
            }
            return (cs_disasm(
                handle,
                (uint8_t *)memory->iwram + (addr & IWRAM_MASK),
                op_len * count,
                addr,
                count,
                insn_ptr
            ));
        case CART_0_START ... CART_0_END:
        case CART_1_START ... CART_1_END:
        case CART_2_START ... CART_2_END:
            if (addr + count * op_len >= CART_0_END) {
                return (0);
            }
            return (cs_disasm(
                handle,
                (uint8_t *)memory->rom + (addr & CART_MASK),
                op_len * count,
                addr,
                count,
                insn_ptr
            ));
        default:
            return (0);
    }
}

void
debugger_cmd_disas_at(
    struct app *app,
    uint32_t ptr,
    bool thumb
) {
    struct memory const *memory;
    cs_insn *insn;
    csh handle;
    size_t count;

    memory = &app->emulation.gba->memory;

    handle = thumb ? app->debugger.handle_thumb : app->debugger.handle_arm;
    count = try_disas(handle, &insn, memory, ptr, thumb, 1);
    if (count == 0) {
        printf("%s<bad>%s", g_light_magenta, g_reset);
    } else {
        printf(
            "%s%s %s%s%s",
            g_light_green,
            insn[0].mnemonic,
            g_light_magenta,
            insn[0].op_str,
            g_reset
        );
    }
}

/*
** NOTE: This function assumes `ptr` is aligned on a word or dword boundary
** (depending on the processor's mode: Thumb or Arm) *AND* that it points
** to valid memory.
*/
static
void
debugger_cmd_disas_around(
    struct app *app,
    uint32_t ptr,
    size_t radius,
    bool thumb
) {
    struct core const *core;
    struct memory const *memory;
    csh handle;
    cs_insn *insn;
    size_t mnemonic_len;
    size_t count;
    size_t op_len;

    uint32_t ptr_start;     // Where the disassembly begins
    uint32_t ptr_end;       // Where it ends

    core = &app->emulation.gba->core;
    memory = &app->emulation.gba->memory;

    op_len = thumb ? 2 : 4;
    handle = thumb ? app->debugger.handle_thumb : app->debugger.handle_arm;

    /* Calculate the value of `ptr_start` */
    {
        size_t i;
        uint32_t tmp;

        i = 0;
        ptr_start = ptr;
        tmp = ptr;
        while (i < radius && tmp > 0) {
            size_t count;

            count = try_disas(handle, &insn, memory, tmp, thumb, 1);
            if (count == 0 && core->cpsr.thumb) {
                tmp -= op_len;
                count = try_disas(handle, &insn, memory, tmp, thumb, 1);
            }
            if (count == 0){
                break;
            }
            ptr_start = tmp;
            tmp -= op_len;
            cs_free(insn, 1);
            ++i;
        }
    }

    /* Calculate the value of `ptr_end` */
    {
        size_t i;

        i = 0;
        ptr_end = ptr;
        while (i < radius) { // && ptr_end < MEMORY_RAW_SIZE) { TODO FIXME
            if (try_disas(handle, &insn, memory, ptr_end, thumb, 1) != 1) {
                break;
            }
            ptr_end += insn[0].size;
            cs_free(insn, 1);
            ++i;
        }
    }

    count = try_disas(
        handle,
        &insn,
        memory,
        ptr_start,
        thumb,
        (ptr_end - ptr_start) / op_len
    );

    mnemonic_len = find_biggest_mnenmonic(insn, count);

    if (mnemonic_len < 5) {
        mnemonic_len = 5;
    }

    /* Print <bad> for instructions that couldn't be disassembled before ptr_start */
    {
        uint32_t p;

        p = ptr - (radius - 1) * op_len;
        while (p < ptr_start) {
            printf(
                " %c %08x: %s%-*s%s\n",
                p == ptr ? '>' : ' ',
                p,
                g_light_green,
                (int)mnemonic_len,
                "<bad>",
                g_reset
            );
            p += op_len;
        }
    }

    {
        size_t i;

        i = 0;
        while (i < count) {
            printf(
                " %c %08x: %s%-*s %s%s%s\n",
                insn[i].address == ptr ? '>' : ' ',
                (uint32_t)insn[i].address,
                g_light_green,
                (int)mnemonic_len,
                insn[i].mnemonic,
                g_light_magenta,
                insn[i].op_str,
                g_reset
            );
            ++i;
        }
    }

    /* Print <bad> for instructions that couldn't be disassembled after ptr_end */
    {
        while (ptr_end < ptr + radius * op_len) {
            printf(
                " %c %08x: %s%-*s%s\n",
                ptr_end == ptr ? '>' : ' ',
                ptr_end,
                g_light_green,
                (int)mnemonic_len,
                "<bad>",
                g_reset
            );
            ptr_end += op_len;
        }
    }

    if (count > 0) {
        cs_free(insn, count);
    }
}

void
debugger_cmd_disas(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    struct core *core;
    bool thumb;
    size_t op_len;
    uint32_t ptr;

    if (!app->debugger.is_started) {
        logln(HS_ERROR, "%s%s%s", g_red, "This command cannot be used when no game is running.", g_reset);
        return;
    }

    core = &app->emulation.gba->core;
    thumb = core->cpsr.thumb;
    op_len = thumb ? 2 : 4;

    if (argc == 0) {
        ptr = core->pc >= op_len * 2 ? core->pc - op_len * 2 : 0;
    } else if (argc == 1) {
        if (debugger_check_arg_type(CMD_DISAS, &argv[0], ARGS_INTEGER)) {
            return ;
        }

        ptr = argv[0].value.i64;
    } else if (argc == 2) {
        char const *mode;

        if (debugger_check_arg_type(CMD_DISAS, &argv[0], ARGS_STRING)
            || debugger_check_arg_type(CMD_DISAS, &argv[1], ARGS_INTEGER)
        ) {
            return ;
        }

        mode = argv[0].value.s;

        if (!strcmp(mode, "t") || !strcmp(mode, "thumb")) {
            thumb = true;
            op_len = 2;
        } else if (!strcmp(mode, "a") || !strcmp(mode, "arm")) {
            thumb = false;
            op_len = 4;
        } else {
            printf("Unknown mode \"%s\".\n", mode);
            return ;
        }

        ptr = argv[1].value.i64;
    } else {
        printf("Usage: %s\n", g_commands[CMD_DISAS].usage);
        return ;
    }

    if (ptr % op_len) {
        printf("The address to disassemble (0x%08x) isn't aligned.\n", ptr);
        return ;
    }

    debugger_cmd_disas_around(
        app,
        ptr,
        5,
        thumb
    );
}
