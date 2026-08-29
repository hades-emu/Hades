/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#pragma once

#include "hades.h"
#include "debugger.h"

struct gba;

struct cheat_token {
    enum {
        CHEAT_TOKEN_KIND_U32,
        CHEAT_TOKEN_KIND_U16,
        CHEAT_TOKEN_KIND_U8,
    } kind;

    union {
        uint32_t u32;
        uint16_t u16;
        uint8_t u8;
    } value;

    struct cheat_token *next;
};

struct cheat_compiler {
    struct cheat_token *tokens;
    struct cheat_token *last;

    char *error;
};

struct cheat_bin {
    struct {
        struct cheat_rom_patch *list;
        size_t len;
        size_t capacity;
    } rom_patches;

    struct {
        struct cheat_insn *list;
        size_t len;
        size_t capacity;
    } insns;

    struct {
        bool active;
        struct sw_breakpoint bp;
    } hook;
};

struct cheat_insn {
    enum cheat_insn_kind {
        CHEAT_INSN_ASSIGN,
    } kind;

    uint32_t width;

    uint32_t addr;
    uint32_t value;

    uint32_t repeat;
};

struct cheat_rom_patch {
    uint32_t addr;
    uint32_t value;
    uint32_t width;
};

struct cheat_parv3_parser {
    uint32_t *data;
    uint32_t idx;
    uint32_t len;
};

void cheat_delete(struct cheat_bin *bin);
void cheat_process_hooks_at_addr(struct gba *gba, uint32_t addr);
struct cheat_insn *cheat_create_insn(struct cheat_bin *bin);
bool cheat_parv3_compile(struct cheat_bin *bin, struct cheat_compiler *compiler);
void cheat_create_rom_patch(struct cheat_bin *bin, uint32_t addr, uint32_t val, uint32_t width);
