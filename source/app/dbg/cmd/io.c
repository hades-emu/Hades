/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

static
uint32_t
debugger_cmd_io_read_register(
    struct app *app,
    struct io_register *reg
) {
    if (reg->size == 2) {
        return (reg->ptr16 ? *reg->ptr16: mem_read16_raw(app->emulation.gba, reg->address));
    } else {
        return (reg->ptr32 ? *reg->ptr32: mem_read32_raw(app->emulation.gba, reg->address));
    }
}

static
void
debugger_cmd_io_dump_binary(
    struct io_register *reg,
    uint32_t value,
    uint32_t size
) {
    int32_t i;

    printf(
        "%s0b%s",
        g_dark_gray,
        g_reset
    );

    size = size ?: reg->size * 8;

    for (i = size - 1; i >= 0; --i) {
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
    uint32_t value,
    uint32_t size
) {
    int32_t i;

    printf(
        "%s0x%s",
        g_dark_gray,
        g_reset
    );

    size = size ?: reg->size * 2;

    for (i = size - 1; i >= 0; --i) {
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

    val = debugger_cmd_io_read_register(app, reg);
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
    debugger_cmd_io_dump_binary(reg, val, 0);

    printf(" (");
    debugger_cmd_io_dump_hex(reg, val, 0);
    printf(")\n");

    for (i = 0; i < reg->bitfield_len; ++i) {
        struct io_bitfield *bitfield;
        uint32_t value;

        bitfield = &reg->bitfield[i];
        value = bitfield_get_range(val, bitfield->start, bitfield->end + 1);

        printf("  %s", value ? g_light_magenta : g_dark_gray);

        // Print in decimal for small numbers, hex for bigs
        if (bitfield->end - bitfield->start >= 8) {
            printf("0x%08x", value);
        } else {
            printf("%10i", value);
        }
        printf(
            "%s | %-30s %s\n",
            g_reset,
            bitfield->label,
            bitfield->hint ?: ""
        );
    }
}

void
debugger_cmd_io(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (!app->debugger.is_started) {
        logln(HS_ERROR, "%s%s%s", g_red, "This command cannot be used when no game is running.", g_reset);
        return;
    }

    if (argc == 0) {
        uint32_t val;
        size_t i;

        printf(
            "|%.12s|%.14s|%.34s|%.36s|%.12s|\n"
            "| %-10s | %-12s | %-32s | %-34s | %-10s |\n"
            "|%.12s|%.14s|%.34s|%.36s|%.12s|\n",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------",
            "Address",
            "Name",
            "Description",
            "Binary",
            "Hex",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------"
        );

        for (i = 0; i < g_io_registers_len; ++i) {
            struct io_register *reg;

            reg = &g_io_registers[i];
            val = debugger_cmd_io_read_register(app, reg);

            printf(
                "| 0x%08x | %s%-12s%s | %-32s | ",
                reg->address,
                g_light_green,
                mem_io_reg_name(reg->address),
                g_reset,
                reg->name
            );
            debugger_cmd_io_dump_binary(reg, val, 32);
            printf(" | ");
            debugger_cmd_io_dump_hex(reg, val, 8);
            printf(" |\n");
        }

        printf(
            "|%.12s|%.14s|%.34s|%.36s|%.12s|\n",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------",
            "-------------------------------------"
        );
    } else if (argc == 1) {
        struct io_register *reg;

        if (debugger_check_arg_type(CMD_IO, &argv[0], ARGS_INTEGER)) {
            return;
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
            return;
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
        return;
    }
}
