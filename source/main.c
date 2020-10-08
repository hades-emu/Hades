/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <capstone/capstone.h>
#include <string.h>
#include "hades.h"
#include "core.h"

/*
square:
        str     fp, [sp, #-4]!
        add     fp, sp, #0
        sub     sp, sp, #12
        str     r0, [fp, #-8]
        ldr     r3, [fp, #-8]
        ldr     r2, [fp, #-8]
        mul     r3, r2, r3
        mov     r0, r3
        add     sp, fp, #0
        ldr     fp, [sp], #4
        bx      lr
*/
/*
uint8_t code[] = "\x04\xb0\x2d\xe5\x00\xb0\x8d\xe2\x0c\xd0\x4d\xe2\x08"
                "\x00\x0b\xe5\x08\x30\x1b\xe5\x08\x20\x1b\xe5\x92\x03"
                "\x03\xe0\x03\x00\xa0\xe1\x00\xd0\x8b\xe2\x04\xb0\x9d"
                "\xe4\x1e\xff\x2f\xe1";
*/

uint8_t code[] = "\x05\x40\xa0\xe3\x0a\x50\xa0\xe3\x95\x04\x04\xe0\x04"
                "\x30\xa0\xe1\x03\x00\xa0\xe1";

int
main(void)
{
    csh handle;
    cs_insn *insn;
    struct core core;

    memset(&core, 0, sizeof(core));

    core.memory_size = 4096 * 16;
    core.memory = malloc(core.memory_size);

    memset(core.memory, 0, core.memory_size);

    memcpy(core.memory, code, sizeof(code));

    core.r13 = 4096 * 10;   // sp
    core.r11 = core.r13;    // fp

    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        panic(ERROR, "Failed to open capstone");
    }

    hs_logln(GLOBAL, "Welcome to Hades");
    hs_logln(GLOBAL, "----------------");

    for (int i = 0; i < 11; ++i) {
        if (cs_disasm(handle, core.memory + core.r15, 4, core.r15, 1, &insn) != 1) {
            hs_logln(DEBUG, "Failed to disassemble opcode (op=%#08x, pc=%#08x)", core.memory[core.r15], core.r15);
        }
        hs_logln(DEBUG, "%s %s", insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, 1);
        core_next_op(&core);
        printf("\n");
    }

    return (0);
}
