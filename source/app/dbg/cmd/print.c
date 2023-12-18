/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <ctype.h>
#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

static
void
debugger_cmd_print_str(
    struct app const *app,
    uint32_t addr,
    size_t align
) {
    uint32_t i;
    uint8_t c;

    i = 0;
    while (true) {
        c = mem_read8_raw(app->emulation.gba, addr + i);
        if (!isprint(c)) {
            break;
        }

        if (i % align == 0) {
            printf("%08x: %s", addr + i, g_light_magenta);
        }
        printf("%c", c);
        if (i % align == align - 1) {
            printf("%s\n", g_reset);
        }
        ++i;
    }
    printf("%s\n", g_reset);
}

static
void
debugger_cmd_print_char(
    struct app const *app,
    uint32_t addr,
    size_t len,
    size_t align
) {
    uint32_t i;

    i = 0;
    while (i < len) {
        char c;

        c = mem_read8_raw(app->emulation.gba, addr + i);
        if (i % align == 0) {
            printf("%08x: %s", addr + i, g_light_magenta);
        }

        printf("%c", isprint(c) ? c : '.');

        if (i % align == align - 1) {
            printf("%s\n", g_reset);
        }
        ++i;
    }
    printf("%s\n", g_reset);
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
    struct app const *app,
    uint32_t start,
    size_t nb,
    size_t align
) {
    uint32_t end;
    size_t len;
    size_t i;

    end = start + nb;

    while (start < end)
    {
        len = end - start;
        if (len >= align) {
            len = align;
        }

        printf("%08x: %s", start, g_light_magenta);

        i = 0;
        while (i < len) {
            printf("%02x ", mem_read8_raw(app->emulation.gba, start + i));
            ++i;
        }
        while (i < align) {
            printf("   ");
            ++i;
        }

        printf("%s|", g_reset);

        i = 0;
        while (i < len) {
            char c;

            c = mem_read8_raw(app->emulation.gba, start + i);
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
    struct app const *app,
    uint32_t start,
    size_t nb,
    size_t align
) {
    uint32_t end;
    size_t len;
    size_t i;

    end = start + nb * 2;

    while (start < end)
    {
        len = (end - start) / 2;
        if (len >= align) {
            len = align;
        }

        printf("%08x: %s", start, g_light_magenta);

        i = 0;
        while (i < len) {
            printf("%04x ", mem_read16_raw(app->emulation.gba, start + i * 2)),
            ++i;
        }
        while (i < align) {
            printf("     ");
            ++i;
        }

        printf("%s|", g_reset);

        i = 0;
        while (i < len * 2) {
            char c;

            c = mem_read8_raw(app->emulation.gba, start + i);
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
    struct app const *app,
    uint32_t start,
    size_t nb,
    size_t align
) {
    uint32_t end;
    size_t len;
    size_t i;

    end = start + nb * 4;

    while (start < end)
    {
        len = (end - start) / 4;
        if (len >= align) {
            len = align;
        }

        printf("%08x: %s", start, g_light_magenta);

        i = 0;
        while (i < len) {
            printf("%08x ", mem_read32_raw(app->emulation.gba, start + i * 4)),
            ++i;
        }
        while (i < align) {
            printf("         ");
            ++i;
        }

        printf("%s|", g_reset);

        i = 0;
        while (i < len * 4) {
            char c;

            c = mem_read8_raw(app->emulation.gba, start + i);
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
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    char const *type;
    size_t quantity;
    uint32_t addr;

    if (!app->debugger.is_started) {
        logln(HS_ERROR, "%s%s%s", g_red, "This command cannot be used when no game is running.", g_reset);
        return;
    }

    if (argc != 2 && argc != 3) {
        printf("Usage: %s\n", g_commands[CMD_PRINT].usage);
        return ;
    }

    if (debugger_check_arg_type(CMD_PRINT, &argv[0], ARGS_STRING)
        || debugger_check_arg_type(CMD_PRINT, &argv[1], ARGS_INTEGER)
        || (argc == 3 && debugger_check_arg_type(CMD_PRINT, &argv[2], ARGS_INTEGER))
    ) {
        return ;
    }

    type = argv[0].value.s;
    if (argc == 2) {
        quantity = 1;
        addr = argv[1].value.i64;
    } else {
        quantity = argv[1].value.i64;
        addr = argv[2].value.i64;
    }

    if (!strcmp(type, "string") || !strcmp(type, "s")) {
        debugger_cmd_print_str(app, addr, 32);
    } else if (!strcmp(type, "char") ||!strcmp(type, "c")) {
        debugger_cmd_print_char(app, addr, quantity, 32);
    } else if (!strcmp(type, "byte") || !strcmp(type, "b") || !strcmp(type, "u8")) {
        debugger_cmd_print_u8(app, addr, quantity, 16);
    } else if (!strcmp(type, "halfword") || !strcmp(type, "h") || !strcmp(type, "u16")) {
        debugger_cmd_print_u16(app, addr, quantity, 8);
    } else if (!strcmp(type, "word") || !strcmp(type, "w") || !strcmp(type, "u32")) {
        debugger_cmd_print_u32(app, addr, quantity, 4);
    } else {
        printf("Invalid type \"%s\". Valid values are 's', 'c', 'b', 'h', and 'w'.\n", type);
    }
}
