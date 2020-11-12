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
#include "memory.h"
#include "core.h"
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
        uint32_t tmp;

        i = 0;
        ptr_start = ptr;
        tmp = ptr;
        while (i < radius && tmp > 0) {
            size_t count;

            count = cs_disasm(handle, core->memory->raw + tmp, 4, tmp, 1, &insn);
            if (count == 0 && core->cpsr.thumb) {
                tmp -= 2;
                count = cs_disasm(handle, core->memory->raw + tmp, 4, tmp, 1, &insn);
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
        while (i < radius && ptr_end < MEMORY_RAW_SIZE) {
            if (cs_disasm(handle, core->memory->raw + ptr_end, 4, ptr_end, 1, &insn) != 1) {
                break;
            }
            ptr_end += insn[0].size;
            cs_free(insn, 1);
            ++i;
        }
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(
        handle,
        core->memory->raw + ptr_start,
        ptr_end - ptr_start,
        ptr_start,
        (ptr_end - ptr_start) / op_len,
        &insn
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
                " %c %08x" RESET ": " LIGHT_GREEN "%-*s" LIGHT_MAGENTA " %s" RESET "\n",
                p == ptr ? '>' : ' ',
                p,
                (int)mnemonic_len,
                "<bad>",
                ""
            );
            p += op_len;
        }
    }

    {
        size_t i;

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
    }

    /* Print <bad> for instructions that couldn't be disassembled after ptr_end */
    {
        while (ptr_end < ptr + radius * op_len) {
            printf(
                " %c %08x" RESET ": " LIGHT_GREEN "%-*s" LIGHT_MAGENTA " %s" RESET "\n",
                ptr_end == ptr ? '>' : ' ',
                ptr_end,
                (int)mnemonic_len,
                "<bad>",
                ""
            );
            ptr_end += op_len;
        }
    }


    cs_free(insn, count);
    // cs_close(handle) ? TODO FIXME
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
        ptr = core->pc - op_len;
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

    if (ptr >= MEMORY_RAW_SIZE) {
        printf("The address to disassemble (0x%08x) is out of memory.\n", ptr);
        return ;
    }

    debugger_cmd_disas_around(
        core,
        ptr,
        5
    );
}
