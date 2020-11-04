/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <ctype.h>
#include "debugger.h"
#include "hades.h"

static
void
debugger_cmd_print_str(
    struct core const *core,
    uint32_t addr,
    size_t align
) {
    uint32_t i;

    i = 0;
    while (addr + i < core->memory_size && isprint(core->memory[addr + i])) {
        if (i % align == 0) {
            printf("%08x: " LIGHT_MAGENTA, addr + i);
        }
        printf("%c", core->memory[addr + i]);
        if (i % align == align - 1) {
            printf(RESET "\n");
        }
        ++i;
    }
    printf(RESET "\n");
}

static
void
debugger_cmd_print_char(
    struct core const *core,
    uint32_t addr,
    size_t len,
    size_t align
) {
    uint32_t i;

    i = 0;
    while (i < len && addr + i < core->memory_size) {
        char c;

        c = core->memory[addr + i];
        if (i % align == 0) {
            printf("%08x: " LIGHT_MAGENTA, addr + i);
        }

        printf("%c", isprint(c) ? c : '.');

        if (i % align == align - 1) {
            printf(RESET "\n");
        }
        ++i;
    }
    printf(RESET "\n");
}

/*
** Dump memory as a pack of bytes, starting at `start` for a total of `nb` bytes.
** A new line is inserted at all `align` bytes.
**
** `start` is assumed to be a valid address. If `nb` is too big, the function
** stopts at the end of memory.
*/
void
debugger_cmd_print_u8(
    struct core const *core,
    uint32_t start,
    size_t nb,
    size_t align
) {
    uint32_t end;
    size_t len;
    size_t i;

    end = start + nb;
    if (end > core->memory_size) {
        end = core->memory_size;
    }

    while (start < end)
    {
        len = end - start;
        if (len >= align) {
            len = align;
        }

        printf("%08x: " LIGHT_MAGENTA, start);

        i = 0;
        while (i < len && start + i < core->memory_size) {
            printf("%02x ", core->memory[start + i]);
            ++i;
        }
        while (i < align) {
            printf("   ");
            ++i;
        }

        printf(RESET "|");

        i = 0;
        while (i < len && start + i < core->memory_size) {
            char c;

            c = core->memory[start + i];
            printf("%c", isprint(c) ? c : '.');

            ++i;
        }
        while (i < align) {
            printf(" ");
            ++i;
        }

        printf("|\n");

        start += align;
    }
}

/*
** Dump memory as a pack of words, starting at `start` for a total of `nb` words.
** A new line is inserted at all `align` words.
**
** `start` is assumed to be a valid address. If `nb` is too big, the function
** stopts at the end of memory.
*/
void
debugger_cmd_print_u16(
    struct core const *core,
    uint32_t start,
    size_t nb,
    size_t align
) {
    uint32_t end;
    size_t len;
    size_t i;

    end = start + nb * 2;
    if (end > core->memory_size - 1) {
        end = core->memory_size;
    }

    while (start < end)
    {
        len = (end - start) / 2;
        if (len >= align) {
            len = align;
        }

        printf("%08x: " LIGHT_MAGENTA, start);

        i = 0;
        while (i < len && start + i * 2 < core->memory_size - 1) {
            printf("%04x ", core_bus_read16(core, start + i * 2)),
            ++i;
        }
        while (i < align) {
            printf("     ");
            ++i;
        }

        printf(RESET "|");

        i = 0;
        while (i < len * 2 && start + i < core->memory_size) {
            char c;

            c = core->memory[start + i];
            printf("%c", isprint(c) ? c : '.');
            ++i;
        }
        while (i < align * 2) {
            printf("  ");
            ++i;
        }

        printf("|\n");

        start += align * 2;
    }
}

/*
** Dump memory as a pack of double-words, starting at `start` for a total of `nb` dwords.
** A new line is inserted at all `align` dwords.
**
** `start` is assumed to be a valid address. If `nb` is too big, the function
** stopts at the end of memory.
*/
void
debugger_cmd_print_u32(
    struct core const *core,
    uint32_t start,
    size_t nb,
    size_t align
) {
    uint32_t end;
    size_t len;
    size_t i;

    end = start + nb * 4;
    if (end > core->memory_size - 3) {
        end = core->memory_size;
    }

    while (start < end)
    {
        len = (end - start) / 4;
        if (len >= align) {
            len = align;
        }

        printf("%08x: " LIGHT_MAGENTA, start);

        i = 0;
        while (i < len && start + i * 4 < core->memory_size - 3) {
            printf("%08x ", core_bus_read32(core, start + i * 4)),
            ++i;
        }
        while (i < align) {
            printf("         ");
            ++i;
        }

        printf(RESET "|");

        i = 0;
        while (i < len * 4 && start + i < core->memory_size) {
            char c;

            c = core->memory[start + i];
            printf("%c", isprint(c) ? c : '.');

            ++i;
        }
        while (i < align * 4) {
            printf("  ");
            ++i;
        }

        printf("|\n");

        start += align * 4;
    }
}

void
debugger_cmd_print(
    struct debugger *debugger,
    size_t argc,
    char const * const *argv
) {
    struct core const *core;
    char const *type;
    size_t quantity;
    uint32_t addr;

    core = debugger->core;
    type = argv[1];
    quantity = debugger_eval_expr(core, argv[2]);
    addr = debugger_eval_expr(core, argv[3]);

    if (addr >= core->memory_size) {
        printf("Address (0x%08x) is out of memory.\n", addr);
        return ;
    }

    if (!strcmp(type, "string") || !strcmp(type, "s")) {
        debugger_cmd_print_str(core, addr, 32);
    } else if (!strcmp(type, "char") ||!strcmp(type, "c")) {
        debugger_cmd_print_char(core, addr, quantity, 32);
    } else if (!strcmp(type, "byte") || !strcmp(type, "b") || !strcmp(type, "u8")) {
        debugger_cmd_print_u8(core, addr, quantity, 16);
    } else if (!strcmp(type, "halfword") || !strcmp(type, "h") || !strcmp(type, "u16")) {
        debugger_cmd_print_u16(core, addr, quantity, 8);
    } else if (!strcmp(type, "word") || !strcmp(type, "w") || !strcmp(type, "u32")) {
        debugger_cmd_print_u32(core, addr, quantity, 4);
    } else {
        printf("Invalid type \"%s\". Valid values are 's', 'c', 'b', 'h', and 'w'.\n", type);
    }
}