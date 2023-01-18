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
#include "dbg/dbg.h"

struct io_register *g_io_registers;
size_t g_io_registers_len;

static
void
debugger_io_push_register(
    struct io_register *reg
) {
    g_io_registers = realloc(g_io_registers, sizeof(struct io_register) * (g_io_registers_len + 1));
    hs_assert(g_io_registers);
    memcpy(g_io_registers + g_io_registers_len, reg, sizeof(struct io_register));
    ++g_io_registers_len;
}

static
void
debugger_io_push_bitrange(
    struct io_register *reg,
    size_t start,
    size_t end,
    char const *label,
    char const *hint
) {
    struct io_bits bits;

    reg->bits = realloc(reg->bits, sizeof(struct io_bits) * (reg->bits_len + 1));
    hs_assert(reg->bits);

    bits.start = start;
    bits.end = end;
    bits.label = label;
    bits.hint = hint;

    memcpy(reg->bits + reg->bits_len, &bits, sizeof(struct io_bits));
    ++reg->bits_len;
}

static
void
debugger_io_push_bit(
    struct io_register *reg,
    size_t bit,
    char const *label,
    char const *hint
) {
    debugger_io_push_bitrange(reg, bit, bit, label, hint);
}

/*
** The name and description provided in this function are from GBATEK.
**   - https://problemkaputt.de/gbatek.htm
*/
void
debugger_io_init(void)
{
    // DISPCNT
    {
        struct io_register reg;

        memset(&reg, 0, sizeof(reg));
        reg.address = IO_REG_DISPCNT;
        reg.size = 2;
        reg.name = "LCD Control";

        debugger_io_push_bitrange(&reg, 0, 2, "BG Mode",                    "(0-5=Video Mode 0-5, 6-7=Prohibited)");
        debugger_io_push_bit(&reg,      3,    "CGB Mode",                   "(0=GBA, 1=CGB; can be set only by BIOS opcodes)");
        debugger_io_push_bit(&reg,      4,    "Display Frame Select",       "(0-1=Frame 0-1) (for BG Modes 4,5 only)");
        debugger_io_push_bit(&reg,      5,    "H-Blank Interval Free",      "(1=Allow access to OAM during H-Blank)");
        debugger_io_push_bit(&reg,      6,    "OBJ Character VRAM Mapping", "(0=Two dimensional, 1=One dimensional)");
        debugger_io_push_bit(&reg,      7,    "Forced Blank",               "(1=Allow FAST access to VRAM, Palette, OAM)");
        debugger_io_push_bit(&reg,      8,    "Screen Display BG0",         "(0=Off, 1=On)");
        debugger_io_push_bit(&reg,      9,    "Screen Display BG1",         "(0=Off, 1=On)");
        debugger_io_push_bit(&reg,      10,   "Screen Display BG2",         "(0=Off, 1=On)");
        debugger_io_push_bit(&reg,      11,   "Screen Display BG3",         "(0=Off, 1=On)");
        debugger_io_push_bit(&reg,      12,   "Screen Display OBJ",         "(0=Off, 1=On)");
        debugger_io_push_bit(&reg,      13,   "Window 0 Display Flag",      "(0=Off, 1=On)");
        debugger_io_push_bit(&reg,      14,   "Window 1 Display Flag",      "(0=Off, 1=On)");
        debugger_io_push_bit(&reg,      15,   "OBJ Window Display Flag",    "(0=Off, 1=On)");
        debugger_io_push_register(&reg);
    }

    // DISPSTAT
    {
        struct io_register reg;

        memset(&reg, 0, sizeof(reg));
        reg.address = IO_REG_DISPSTAT;
        reg.size = 2;
        reg.name = "General LCD Status";

        debugger_io_push_bit(&reg,      0,      "V-Blank flag",                 "(1=VBlank) (set in line 160..226; not 227)");
        debugger_io_push_bit(&reg,      1,      "H-Blank flag",                 "(1=HBlank) (toggled in all lines, 0..227)");
        debugger_io_push_bit(&reg,      2,      "V-Counter flag",               "(1=Match)  (set in selected line)");
        debugger_io_push_bit(&reg,      3,      "V-Blank IRQ Enable",           "(1=Enable)");
        debugger_io_push_bit(&reg,      4,      "H-Blank IRQ Enable",           "(1=Enable)");
        debugger_io_push_bit(&reg,      5,      "V-Counter IRQ Enable",         "(1=Enable)");
        debugger_io_push_bit(&reg,      6,      "Reserved (0)",                 NULL);
        debugger_io_push_bit(&reg,      7,      "Reserved (0)",                 NULL);
        debugger_io_push_bitrange(&reg, 8, 15,  "V-Count Setting",              NULL);

        debugger_io_push_register(&reg);
    }
}

struct io_register *
debugger_io_lookup_reg(
    uint32_t address
) {
    size_t i;

    for (i = 0; i < g_io_registers_len; ++i) {
        struct io_register *reg;

        reg = &g_io_registers[i];
        if (address == (reg->address & ~(reg->size - 1))) {
            return (reg);
        }
    }
    return (NULL);
}
