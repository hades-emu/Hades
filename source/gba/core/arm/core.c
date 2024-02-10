/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include "gba/gba.h"
#include "gba/core/arm.h"

static struct hs_arm_insn const arm_insns[] = {

    // Data processing
    { "and_reg1",   "xxxx_000_0000_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "and_reg2",   "xxxx_000_0000_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "and_val",    "xxxx_001_0000_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "eor_reg1",   "xxxx_000_0001_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "eor_reg2",   "xxxx_000_0001_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "eor_val",    "xxxx_001_0001_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "sub_reg1",   "xxxx_000_0010_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "sub_reg2",   "xxxx_000_0010_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "sub_val",    "xxxx_001_0010_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "rsb_reg1",   "xxxx_000_0011_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "rsb_reg2",   "xxxx_000_0011_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "rsb_val",    "xxxx_001_0011_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "add_reg1",   "xxxx_000_0100_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "add_reg2",   "xxxx_000_0100_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "add_val",    "xxxx_001_0100_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "adc_reg1",   "xxxx_000_0101_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "adc_reg2",   "xxxx_000_0101_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "adc_val",    "xxxx_001_0101_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "sbc_reg1",   "xxxx_000_0110_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "sbc_reg2",   "xxxx_000_0110_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "sbc_val",    "xxxx_001_0110_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "rsc_reg1",   "xxxx_000_0111_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "rsc_reg2",   "xxxx_000_0111_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "rsc_val",    "xxxx_001_0111_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "tst_reg1",   "xxxx_000_1000_1_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "tst_reg2",   "xxxx_000_1000_1_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "tst_val",    "xxxx_001_1000_1_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "teq_reg1",   "xxxx_000_1001_1_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "teq_reg2",   "xxxx_000_1001_1_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "teq_val",    "xxxx_001_1001_1_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "cmp_reg1",   "xxxx_000_1010_1_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "cmp_reg2",   "xxxx_000_1010_1_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "cmp_val",    "xxxx_001_1010_1_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "cmn_reg1",   "xxxx_000_1011_1_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "cmn_reg2",   "xxxx_000_1011_1_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "cmn_val",    "xxxx_001_1011_1_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "orr_reg1",   "xxxx_000_1100_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "orr_reg2",   "xxxx_000_1100_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "orr_val",    "xxxx_001_1100_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "mov_reg1",   "xxxx_000_1101_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "mov_reg2",   "xxxx_000_1101_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "mov_val",    "xxxx_001_1101_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "bic_reg1",   "xxxx_000_1110_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "bic_reg2",   "xxxx_000_1110_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "bic_val",    "xxxx_001_1110_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    { "mvn_reg1",   "xxxx_000_1111_s_xxxxxxxxxxxxxxx0xxxx",             core_arm_alu},
    { "mvn_reg2",   "xxxx_000_1111_s_xxxxxxxxxxxx0xx1xxxx",             core_arm_alu},
    { "mvn_val",    "xxxx_001_1111_s_xxxxxxxxxxxxxxxxxxxx",             core_arm_alu},

    // PSR Transfers
    { "mrs",        "xxxx_00010_p_001111_dddd_000000000000",            core_arm_mrs},
    { "msr_imm",    "xxxx_00110_p_10_xxxx_1111_rrrr_iiiiiiii",          core_arm_msr},
    { "msr_reg",    "xxxx_00010_p_10_xxxx_1111_00000000_mmmm",          core_arm_msr},

    // Multiply and Multiply-Accumulate (MUL, MLA)
    { "mul",        "xxxx_000000_0_s_ddddnnnnssss_1001_mmmm",           core_arm_mul},
    { "mla",        "xxxx_000000_1_s_ddddnnnnssss_1001_mmmm",           core_arm_mul},

    // Multiply Long and Multiply-Accumulate Long ({U,I}MULL, {U,I}MLAL)
    { "umull",       "xxxx_00001_00_s_ddddnnnnssss_1001_mmmm",          core_arm_mull},
    { "umlal",       "xxxx_00001_01_s_ddddnnnnssss_1001_mmmm",          core_arm_mull},
    { "imull",       "xxxx_00001_10_s_ddddnnnnssss_1001_mmmm",          core_arm_mull},
    { "imlal",       "xxxx_00001_11_s_ddddnnnnssss_1001_mmmm",          core_arm_mull},

    // Branch
    {"b",           "xxxx_101_0_xxxxxxxxxxxxxxxxxxxxxxxx",              core_arm_branch},
    {"bl",          "xxxx_101_1_xxxxxxxxxxxxxxxxxxxxxxxx",              core_arm_branch},
    {"bx",          "xxxx_0001_0010_1111_1111_1111_0001_xxxx",          core_arm_branch_xchg},

    // Block data transfer
    {"push",         "xxxx_100_pusw0_xxxx_xxxxxxxxxxxxxxxx",            core_arm_bdt},
    {"pop",         "xxxx_100_pusw1_xxxx_xxxxxxxxxxxxxxxx",             core_arm_bdt},

    // Single Data Transfer
    {"str",         "xxxx_01_ipubw0_xxxx_xxxx_xxxxxxxxxxxx",            core_arm_sdt},
    {"ldr",         "xxxx_01_ipubw1_xxxx_xxxx_xxxxxxxxxxxx",            core_arm_sdt},

    // Halfword and Signed Data Transfer
    {"strh_imm",    "xxxx_000_pu0w0_xxxx_xxxx_0000_1011xxxx",           core_arm_hsdt},
    {"strh_reg",    "xxxx_000_pu1w0_xxxx_xxxx_xxxx_1011xxxx",           core_arm_hsdt},

    {"strsb_imm",   "xxxx_000_pu0w0_xxxx_xxxx_0000_1101xxxx",           core_arm_hsdt},
    {"strsb_reg",   "xxxx_000_pu1w0_xxxx_xxxx_xxxx_1101xxxx",           core_arm_hsdt},

    {"strsh_imm",   "xxxx_000_pu0w0_xxxx_xxxx_0000_1111xxxx",           core_arm_hsdt},
    {"strsh_reg",   "xxxx_000_pu1w0_xxxx_xxxx_xxxx_1111xxxx",           core_arm_hsdt},

    {"ldrh_imm",    "xxxx_000_pu0w1_xxxx_xxxx_0000_1011xxxx",           core_arm_hsdt},
    {"ldrh_reg",    "xxxx_000_pu1w1_xxxx_xxxx_xxxx_1011xxxx",           core_arm_hsdt},

    {"ldrsb_imm",   "xxxx_000_pu0w1_xxxx_xxxx_0000_1101xxxx",           core_arm_hsdt},
    {"ldrsb_reg",   "xxxx_000_pu1w1_xxxx_xxxx_xxxx_1101xxxx",           core_arm_hsdt},

    {"ldrsh_imm",   "xxxx_000_pu0w1_xxxx_xxxx_0000_1111xxxx",           core_arm_hsdt},
    {"ldrsh_reg",   "xxxx_000_pu1w1_xxxx_xxxx_xxxx_1111xxxx",           core_arm_hsdt},

    // Software Interrupt
    {"swi",         "xxxx_1111_xxxxxxxxxxxxxxxxxxxxxxxx",               core_arm_swi},

    // Single Data Swap
    {"swp",         "xxxx_00010_b_00nnnndddd00001001mmmm",              core_arm_swp},
};

static size_t const arm_insns_len = array_length(arm_insns);

void (*arm_lut[4096])(struct gba *gba, uint32_t op) = { 0 };
bool cond_lut[256];

void
core_arm_decode_insns(void)
{
    struct hs_arm_decoded_insn arm_decoded_insns[arm_insns_len];
    size_t i;

    for (i = 0; i < arm_insns_len; ++i) {
        struct hs_arm_insn const *encoded_insn;
        struct hs_arm_decoded_insn *decoded_insn;
        size_t j;
        size_t k;

        encoded_insn = arm_insns + i;
        decoded_insn = arm_decoded_insns + i;

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

        if (k != 32) {
            panic(
                HS_CORE,
                "instruction \"%s\" doesn't have a length of 32 bits",
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
            if (!(((decoded_insn->value ^ arm_decoded_insns[j].value) & decoded_insn->mask) & arm_decoded_insns[j].mask)) {
                panic(
                    HS_CORE,
                    "instruction \"%s\" collides with \"%s\".",
                    encoded_insn->name,
                    arm_insns[j].name
                );
            }
            ++j;
        }
    }

    /*
    ** Build the lookup table for ARM instructions.
    */

    for (i = 0; i < array_length(arm_lut); ++i) {
        uint32_t op;
        size_t j;

        op = ((i & 0xFF0) << 16) | ((i & 0xF) << 4);
        for (j = 0; j < arm_insns_len; ++j) {
            if ((op & arm_decoded_insns[j].mask & 0x0FF000F0) == (arm_decoded_insns[j].value & 0x0FF000F0)) {

                // Check for double matches, which means the LUT is too small and ambiguous.
                hs_assert(!arm_lut[i]);
                arm_lut[i] = arm_insns[j].op;
            }
        }
    }

    /*
    ** Build the conditions lookup table for ARM instructions.
    */

    for (i = 0; i < array_length(cond_lut); ++i) {
        bool o;
        bool c;
        bool z;
        bool n;

        o = bitfield_get(i, 4);
        c = bitfield_get(i, 5);
        z = bitfield_get(i, 6);
        n = bitfield_get(i, 7);
        switch (bitfield_get_range(i, 0, 4)) {
            case COND_EQ: cond_lut[i] = z; break;
            case COND_NE: cond_lut[i] = !z; break;
            case COND_CS: cond_lut[i] = c; break;
            case COND_CC: cond_lut[i] = !c; break;
            case COND_MI: cond_lut[i] = n; break;
            case COND_PL: cond_lut[i] = !n; break;
            case COND_VS: cond_lut[i] = o; break;
            case COND_VC: cond_lut[i] = !o; break;
            case COND_HI: cond_lut[i] = c && !z; break;
            case COND_LS: cond_lut[i] = !c || z; break;
            case COND_GE: cond_lut[i] = n == o; break;
            case COND_LT: cond_lut[i] = n != o; break;
            case COND_GT: cond_lut[i] = !z && (n == o); break;
            case COND_LE: cond_lut[i] = z || (n != o); break;
            case COND_AL: cond_lut[i] = true; break;
            default:      cond_lut[i] = false; break;
        }
    }
}
