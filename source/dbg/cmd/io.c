/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "app.h"
#include "dbg/dbg.h"

static
void
debugger_cmd_io_dump_binary(
    struct io_register *reg,
    uint32_t value
) {
    int32_t i;

    printf(
        "%s0b%s",
        g_dark_gray,
        g_reset
    );

    for (i = reg->size * 8 - 1; i >= 0; --i) {
        bool b;

        b = value & (1 << i);
        printf(
            "%s%c%s",
            b ? g_light_magenta : g_dark_gray,
            '0' + b,
            g_reset
        );
    }
}

static
void
debugger_cmd_io_dump_hex(
    struct io_register *reg,
    uint32_t value
) {
    int32_t i;

    printf(
        "%s0x%s",
        g_dark_gray,
        g_reset
    );

    for (i = reg->size * 2 - 1; i >= 0; --i) {
        uint8_t x;

        x = (value >> (i * 4)) & 0xF;
        printf(
            "%s%x%s",
            x ? g_light_magenta : g_dark_gray,
            x,
            g_reset
        );
    }
}

static
void
debugger_cmd_io_dump_reg(
    struct app *app,
    struct io_register *reg
) {
    size_t i;
    uint32_t val;

    if (reg->size == 2) {
        val = mem_read16_raw(app->emulation.gba, reg->address);
    } else {
        val = mem_read32_raw(app->emulation.gba, reg->address);
    }
    printf(
        "%sRegister%s: %s%s%s (%s%s%s)\n",
        g_light_green,
        g_reset,
        g_light_magenta,
        mem_io_reg_name(reg->address),
        g_reset,
        g_light_magenta,
        reg->name,
        g_reset
    );
    printf(
        "%sValue%s: ",
        g_light_green,
        g_reset
    );
    debugger_cmd_io_dump_binary(reg, val);

    printf(" (");
    debugger_cmd_io_dump_hex(reg, val);
    printf(")\n");

    for (i = 0; i < reg->bits_len; ++i) {
        struct io_bits *bits;
        uint32_t value;

        bits = &reg->bits[i];
        value = bitfield_get_range(val, bits->start, bits->end + 1);
        printf(
            "%s%3i%s | %-30s %s\n",
            value ? g_light_magenta : g_dark_gray,
            value,
            g_reset,
            bits->label,
            bits->hint
        );
    }
}

void
debugger_cmd_io(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (argc == 0) {
        uint32_t val;
        size_t i;

        printf(
            "| %-8s | %-18s | %-18s | %-6s |\n"
            "|%.10s|%.20s|%.20s|%.8s|\n",
            "Name",
            "Description",
            "Binary",
            "Hex",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------"
        );

        for (i = 0; i < g_io_registers_len; ++i) {
            struct io_register *reg;

            reg = &g_io_registers[i];
            if (reg->size == 2) {
                val = mem_read16_raw(app->emulation.gba, reg->address);
            } else {
                val = mem_read32_raw(app->emulation.gba, reg->address);
            }

            printf(
                "| %s%-8s%s | %s%-18s%s | ",
                g_light_green,
                mem_io_reg_name(reg->address),
                g_reset,
                g_light_green,
                reg->name,
                g_reset
            );
            debugger_cmd_io_dump_binary(reg, val);
            printf(" | ");
            debugger_cmd_io_dump_hex(reg, val);
            printf(" |\n");
        }

        printf(
            "|%.10s|%.20s|%.20s|%.8s|\n",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------"
        );
    } else if (argc == 1) {
        struct io_register *reg;

        if (debugger_check_arg_type(CMD_IO, &argv[0], ARGS_INTEGER)) {
            return ;
        }

        reg = debugger_io_lookup_reg(argv[0].value.i64);
        if (reg) {
            debugger_cmd_io_dump_reg(app, reg);
        } else {
            printf(
                "Unknown IO register at address %s%08x%s.\n",
                g_light_magenta,
                (uint32_t)argv[0].value.i64,
                g_reset
            );
        }
    } else if (argc == 2) {
        struct io_register *reg;

        if (
            debugger_check_arg_type(CMD_IO, &argv[0], ARGS_INTEGER)
            || debugger_check_arg_type(CMD_IO, &argv[1], ARGS_INTEGER)
        ) {
            return ;
        }

        reg = debugger_io_lookup_reg(argv[0].value.i64);
        if (reg) {
            if (reg->size == 2) {
                mem_write16_raw(app->emulation.gba, reg->address, argv[1].value.i64);
                debugger_cmd_io_dump_reg(app, reg);
            } else {
                mem_write32_raw(app->emulation.gba, reg->address, argv[1].value.i64);
                debugger_cmd_io_dump_reg(app, reg);
            }
        } else {
            printf(
                "Unknown IO register at address %s%08x%s.\n",
                g_light_magenta,
                (uint32_t)argv[0].value.i64,
                g_reset
            );
        }
    } else {
        printf("Usage: %s\n", g_commands[CMD_IO].usage);
        return ;
    }
}
