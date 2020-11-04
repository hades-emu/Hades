/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <capstone/arm.h>
#include <capstone/capstone.h>
#include <string.h>
#include "debugger.h"
#include "hades.h"

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

/*
** NOTE: This function assumes `ptr` is aligned on a word or dword boundary
** (depending on the processor's mode: Thumb or Arm) *AND* that it points
** to valid memory.
*/
static
void
debugger_cmd_disas_around(
    struct core *core,
    uint32_t ptr,
    size_t radius
) {
    csh handle;
    cs_mode mode;
    cs_insn *insn;
    size_t mnemonic_len;
    size_t count;
    size_t i;

    uint32_t ptr_start;     // Where the disassembly begins
    uint32_t ptr_end;       // Where it ends
    size_t op_len;          // Size of an instruction

    op_len = core->cpsr.thumb ? 2 : 4;

    mode = 0;
    mode |= (core->cpsr.thumb ? CS_MODE_THUMB : CS_MODE_ARM);
    mode |= (core->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);

    if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK) {
        printf("Failed to open capstone.\n");
        return ;
    }

    /* Calculate the value of `ptr_start` */
    {
        size_t i;

        i = 0;
        ptr_start = ptr;
        while (i < radius && ptr_start > 0) {
            if (cs_disasm(handle, core->memory + ptr_start, op_len, ptr_start, 1, &insn) != 1) {
                break;
            }
            cs_free(insn, 1);
            ptr_start -= op_len;
            ++i;
        }
    }

    /* Calculate the value of `ptr_end` */
    {
        size_t i;

        i = 0;
        ptr_end = ptr;
        while (i < radius + 1 && ptr_end < core->memory_size) {
            if (cs_disasm(handle, core->memory + ptr_end, op_len, ptr_end, 1, &insn) != 1) {
                break;
            }
            cs_free(insn, 1);
            ptr_end += op_len;
            ++i;
        }
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(
        handle,
        core->memory + ptr_start,
        ptr_end - ptr_start,
        ptr_start,
        (ptr_end - ptr_start) / op_len,
        &insn
    );

    mnemonic_len = find_biggest_mnenmonic(insn, count);

    i = 0;
    while (i < count) {
        printf(
            " %c %08x" RESET ": " LIGHT_GREEN "%-*s" LIGHT_MAGENTA " %s" RESET "\n",
            insn[i].address == ptr ? '>' : ' ',
            (uint32_t)insn[i].address,
            (int)mnemonic_len,
            insn[i].mnemonic,
            insn[i].op_str
        );
        ++i;
    }

    cs_free(insn, count);
}

void
debugger_cmd_disas(
    struct debugger *debugger,
    size_t argc,
    char const * const *argv
) {
    struct core *core;
    size_t op_len;
    uint32_t ptr;

    core = debugger->core;
    op_len = core->cpsr.thumb ? 2 : 4;

    if (argc == 1) {
        ptr = core->r15 - op_len;
    } else if (argc == 2) {
        ptr = debugger_eval_expr(core, argv[1]);
    } else {
        printf("Usage: %s\n", g_commands[CMD_DISAS].usage);
        return ;
    }

    if (ptr % op_len) {
        printf("The address to disassemble (0x%08x) isn't aligned.\n", ptr);
        return ;
    }

    if (ptr >= core->memory_size) {
        printf("The address to disassemble (0x%08x) is out of memory.\n", ptr);
        return ;
    }

    debugger_cmd_disas_around(
        core,
        ptr,
        4
    );
}
