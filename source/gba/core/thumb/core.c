/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include "gba/gba.h"
#include "gba/core/thumb.h"

static struct hs_thumb_insn const thumb_insns[] = {
    // Move shifted register
    { "lsl",            "00000yyyyysssddd",          core_thumb_lsl},
    { "lsr",            "00001yyyyysssddd",          core_thumb_lsr},
    { "asr",            "00010yyyyysssddd",          core_thumb_asr},

    // Add/Subtract from/to low registers
    { "add_lo_reg",     "00011i0yyysssddd",          core_thumb_lo_add},
    { "sub_lo_reg",     "00011i1yyysssddd",          core_thumb_lo_sub},

    // Move/Compare/Add/Subtract immediate
    { "mov_imm",        "00100dddxxxxxxxx",          core_thumb_mov_imm},
    { "cmp_imm",        "00101dddxxxxxxxx",          core_thumb_cmp_imm},
    { "add_imm",        "00110dddxxxxxxxx",          core_thumb_add_imm},
    { "sub_imm",        "00111dddxxxxxxxx",          core_thumb_sub_imm},

    // ALU operations
    { "alu",            "010000xxxxsssddd",          core_thumb_alu},

    // Hi register operations/Branch exchange
    { "add_hi_reg",     "01000100hhsssddd",          core_thumb_hi_add},
    { "cmp_hi_reg",     "01000101hhsssddd",          core_thumb_hi_cmp},
    { "mov_hi_reg",     "01000110hhsssddd",          core_thumb_hi_mov},
    { "bx",             "01000111hhsssddd",          core_thumb_branch_xchg},

    // PC-Relative loads
    { "ldr_pc",         "01001dddxxxxxxxx",          core_thumb_ldr_pc},

    // Load/Store Word/Byte with register offset
    { "ldr_regoff",     "01011b0ooobbbddd",          core_thumb_sdt_wb_reg},
    { "str_regoff",     "01010b0ooobbbddd",          core_thumb_sdt_wb_reg},

    // Load/Store Sign-Extended Byte/Halfword
    { "sdt_sbh_reg",    "0101hs1ooobbbddd",          core_thumb_sdt_sbh_reg},

    // Load/Store with Immediate Offset
    { "std_imm",        "011blooooobbbddd",          core_thumb_sdt_imm},

    // Load/Store Halfword with Immediate Offset
    { "std_h_imm",      "1000looooobbbddd",          core_thumb_sdt_h_imm},

    // SP-Relative Load/Store
    { "sdt_sp",         "1001ldddiiiiiiii",          core_thumb_sdt_sp},

    // Load Address
    { "add_pc_imm",     "10100dddiiiiiiii",          core_thumb_add_pc_imm},
    { "add_sp_imm",     "10101dddiiiiiiii",          core_thumb_add_sp_imm},

    // Add Offset to Stack Pointer
    { "add_sp_s_imm",   "10110000siiiiiii",          core_thumb_add_sp_s_imm},

    // Push/Pop lo registers
    { "push",           "1011010xxxxxxxxx",          core_thumb_push},
    { "pop",            "1011110xxxxxxxxx",          core_thumb_pop},

    // Multiple Load/Store
    { "stmia",          "11000bbbxxxxxxxx",          core_thumb_stmia},
    { "ldmia",          "11001bbbxxxxxxxx",          core_thumb_ldmia},

    // Conditional Branch
    { "beq",            "11010000xxxxxxxx",          core_thumb_branch_cond},
    { "bne",            "11010001xxxxxxxx",          core_thumb_branch_cond},
    { "bcs",            "11010010xxxxxxxx",          core_thumb_branch_cond},
    { "bcc",            "11010011xxxxxxxx",          core_thumb_branch_cond},
    { "bmi",            "11010100xxxxxxxx",          core_thumb_branch_cond},
    { "bpl",            "11010101xxxxxxxx",          core_thumb_branch_cond},
    { "bvs",            "11010110xxxxxxxx",          core_thumb_branch_cond},
    { "bvc",            "11010111xxxxxxxx",          core_thumb_branch_cond},
    { "bhi",            "11011000xxxxxxxx",          core_thumb_branch_cond},
    { "bls",            "11011001xxxxxxxx",          core_thumb_branch_cond},
    { "bge",            "11011010xxxxxxxx",          core_thumb_branch_cond},
    { "blt",            "11011011xxxxxxxx",          core_thumb_branch_cond},
    { "bgt",            "11011100xxxxxxxx",          core_thumb_branch_cond},
    { "ble",            "11011101xxxxxxxx",          core_thumb_branch_cond},

    // Software Interrupt
    { "swi",            "11011111xxxxxxxx",          core_thumb_swi},

    // Unconditional Branch (B)
    { "b",              "11100xxxxxxxxxxx",          core_thumb_branch},

    // Long Branch with Link (BL)
    { "bl_1",           "11110xxxxxxxxxxx",          core_thumb_branch_link},
    { "bl_2",           "11111xxxxxxxxxxx",          core_thumb_branch_link},
};

static size_t const thumb_insns_len = ARRAY_LEN(thumb_insns);

void (*thumb_lut[256])(struct gba *gba, uint16_t op) = { 0 };

void
core_thumb_decode_insns(void)
{
    struct hs_thumb_decoded_insn thumb_decoded_insns[thumb_insns_len];
    size_t i;

    for (i = 0; i < thumb_insns_len; ++i) {
        struct hs_thumb_insn const *encoded_insn;
        struct hs_thumb_decoded_insn *decoded_insn;
        size_t j;
        size_t k;

        encoded_insn = thumb_insns + i;
        decoded_insn = thumb_decoded_insns + i;

        /*
        ** Decode the user-friendly string mask into two values: decoded_insn->mask and decoded_insn->value.
        */
        j = 0; // Iterator over all the chars of `encoded_insn->mask`
        k = 0; // Counter of non-separator characters of `encoded_insn->mask`
        while (encoded_insn->mask[j]) {
            if (encoded_insn->mask[j] != '_') { // Skip separators

                decoded_insn->mask <<= 1;
                decoded_insn->value <<= 1;

                if (encoded_insn->mask[j] == '0' || encoded_insn->mask[j] == '1') {
                    decoded_insn->mask |= 1;
                    decoded_insn->value |= (encoded_insn->mask[j] - '0');
                }
                ++k;
            }
            ++j;
        }

        if (k != 16) {
            panic(
                HS_CORE,
                "instruction \"%s\" doesn't have a length of 16 bits",
                encoded_insn->name
            );
        }

        /*
        ** Ensure we don't have a collision with an existing instruction.
        **
        ** To do that, we must verify that there's at least one difference between
        ** the instruction we want to add and all other instructions.
        **
        ** By difference, we mean at least one bit in common in the mask of both
        ** instructions that maps to different values.
        */
        j = 0;
        while (j < i) {
            if (!(((decoded_insn->value ^ thumb_decoded_insns[j].value) & decoded_insn->mask) & thumb_decoded_insns[j].mask)) {
                panic(
                    HS_CORE,
                    "instruction \"%s\" collides with \"%s\".",
                    encoded_insn->name,
                    thumb_insns[j].name
                );
            }
            ++j;
        }
    }

    /*
    ** Build the lookup table for thumb instructions.
    */

    for (i = 0; i < ARRAY_LEN(thumb_lut); ++i) {
        uint16_t op;
        size_t j;

        op = i << 8;
        for (j = 0; j < thumb_insns_len; ++j) {
            if ((op & thumb_decoded_insns[j].mask & 0xFF00) == (thumb_decoded_insns[j].value & 0xFF00)) {

                // Check for double matches, which means the LUT is too small and ambiguous.
                hs_assert(!thumb_lut[i]);
                thumb_lut[i] = thumb_insns[j].op;
            }
        }
    }
}
