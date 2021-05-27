/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "core/arm.h"
#include "gba.h"

static struct arm_encoded_insn arm_encoded_insns[] = {

    // Data processing
    { "and_reg1",   "xxxx_000_0000_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "and_reg2",   "xxxx_000_0000_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "and_val",    "xxxx_001_0000_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "eor_reg1",   "xxxx_000_0001_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "eor_reg2",   "xxxx_000_0001_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "eor_val",    "xxxx_001_0001_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "sub_reg1",   "xxxx_000_0010_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "sub_reg2",   "xxxx_000_0010_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "sub_val",    "xxxx_001_0010_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "rsb_reg1",   "xxxx_000_0011_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "rsb_reg2",   "xxxx_000_0011_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "rsb_val",    "xxxx_001_0011_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "add_reg1",   "xxxx_000_0100_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "add_reg2",   "xxxx_000_0100_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "add_val",    "xxxx_001_0100_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "adc_reg1",   "xxxx_000_0101_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "adc_reg2",   "xxxx_000_0101_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "adc_val",    "xxxx_001_0101_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "sbc_reg1",   "xxxx_000_0110_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "sbc_reg2",   "xxxx_000_0110_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "sbc_val",    "xxxx_001_0110_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "rsc_reg1",   "xxxx_000_0111_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "rsc_reg2",   "xxxx_000_0111_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "rsc_val",    "xxxx_001_0111_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "tst_reg1",   "xxxx_000_1000_1_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "tst_reg2",   "xxxx_000_1000_1_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "tst_val",    "xxxx_001_1000_1_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "teq_reg1",   "xxxx_000_1001_1_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "teq_reg2",   "xxxx_000_1001_1_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "teq_val",    "xxxx_001_1001_1_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "cmp_reg1",   "xxxx_000_1010_1_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "cmp_reg2",   "xxxx_000_1010_1_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "cmp_val",    "xxxx_001_1010_1_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "cmn_reg1",   "xxxx_000_1011_1_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "cmn_reg2",   "xxxx_000_1011_1_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "cmn_val",    "xxxx_001_1011_1_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "orr_reg1",   "xxxx_000_1100_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "orr_reg2",   "xxxx_000_1100_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "orr_val",    "xxxx_001_1100_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "mov_reg1",   "xxxx_000_1101_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "mov_reg2",   "xxxx_000_1101_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "mov_val",    "xxxx_001_1101_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "bic_reg1",   "xxxx_000_1110_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "bic_reg2",   "xxxx_000_1110_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "bic_val",    "xxxx_001_1110_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    { "mvn_reg1",   "xxxx_000_1111_s_xxxxxxxxxxxxxxx0xxxx",          core_arm_alu},
    { "mvn_reg2",   "xxxx_000_1111_s_xxxxxxxxxxxx0xx1xxxx",          core_arm_alu},
    { "mvn_val",    "xxxx_001_1111_s_xxxxxxxxxxxxxxxxxxxx",          core_arm_alu},

    // PSR Transfers
    { "mrs",        "xxxx_00010_p_001111_dddd_000000000000",         core_arm_mrs},
    { "msr",        "xxxx_00010_p_1010011111_00000000_mmmm",         core_arm_msr},
    { "msrf_imm",   "xxxx_00110_p_1010001111_rrrr_iiiiiiii",         core_arm_msrf},
    { "msrf_reg",   "xxxx_00010_p_1010001111_00000000_mmmm",         core_arm_msrf},

    // Multiply and Multiply-Accumulate (MUL, MLA)
    { "mul",        "xxxx_000000_0_s_ddddnnnnssss_1001_mmmm",         core_arm_mul},
    { "mla",        "xxxx_000000_1_s_ddddnnnnssss_1001_mmmm",         core_arm_mul},

    // Branch
    {"b",           "xxxx_101_0_xxxxxxxxxxxxxxxxxxxxxxxx",           core_arm_branch},
    {"bl",          "xxxx_101_1_xxxxxxxxxxxxxxxxxxxxxxxx",           core_arm_branch},
    {"bx",          "xxxx_0001_0010_1111_1111_1111_0001_xxxx",       core_arm_branch_xchg},

    // Block data transfer
    {"push",         "xxxx_100_pusw0_xxxx_xxxxxxxxxxxxxxxx",         core_arm_bdt},
    {"pop",         "xxxx_100_pusw1_xxxx_xxxxxxxxxxxxxxxx",          core_arm_bdt},

    // Single Data Transfer
    {"str",         "xxxx_01_ipubw0_xxxx_xxxx_xxxxxxxxxxxx",         core_arm_sdt},
    {"ldr",         "xxxx_01_ipubw1_xxxx_xxxx_xxxxxxxxxxxx",         core_arm_sdt},

    // Halfword and Signed Data Transfer
    {"strh_imm",    "xxxx_000_pu0w0_xxxx_xxxx_0000_1011xxxx",         core_arm_hsdt},
    {"strh_reg",    "xxxx_000_pu1w0_xxxx_xxxx_xxxx_1011xxxx",         core_arm_hsdt},

    {"strsb_imm",   "xxxx_000_pu0w0_xxxx_xxxx_0000_1101xxxx",         core_arm_hsdt},
    {"strsb_reg",   "xxxx_000_pu1w0_xxxx_xxxx_xxxx_1101xxxx",         core_arm_hsdt},

    {"strsh_imm",   "xxxx_000_pu0w0_xxxx_xxxx_0000_1111xxxx",         core_arm_hsdt},
    {"strsh_reg",   "xxxx_000_pu1w0_xxxx_xxxx_xxxx_1111xxxx",         core_arm_hsdt},

    {"ldrh_imm",    "xxxx_000_pu0w1_xxxx_xxxx_0000_1011xxxx",         core_arm_hsdt},
    {"ldrh_reg",    "xxxx_000_pu1w1_xxxx_xxxx_xxxx_1011xxxx",         core_arm_hsdt},

    {"ldrsb_imm",   "xxxx_000_pu0w1_xxxx_xxxx_0000_1101xxxx",         core_arm_hsdt},
    {"ldrsb_reg",   "xxxx_000_pu1w1_xxxx_xxxx_xxxx_1101xxxx",         core_arm_hsdt},

    {"ldrsh_imm",   "xxxx_000_pu0w1_xxxx_xxxx_0000_1111xxxx",         core_arm_hsdt},
    {"ldrsh_reg",   "xxxx_000_pu1w1_xxxx_xxxx_xxxx_1111xxxx",         core_arm_hsdt},

    // Software Interrupt
    {"swi",         "xxxx_1111_xxxxxxxxxxxxxxxxxxxxxxxx",           core_arm_swi},
};

struct arm_insn arm_insns[ARRAY_LEN(arm_encoded_insns)] = { 0 };

size_t arm_insns_len = ARRAY_LEN(arm_encoded_insns);

void
core_arm_decode_insns(void)
{
    size_t i;

    i = 0;
    while (i < arm_insns_len) {
        struct arm_encoded_insn *encoded_insn;
        struct arm_insn *decoded_insn;
        size_t j;
        size_t k;

        encoded_insn = arm_encoded_insns + i;
        decoded_insn = arm_insns + i;

        decoded_insn->name = encoded_insn->name;
        decoded_insn->op = encoded_insn->op;

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

#if DEBUG
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
            if (!(((decoded_insn->value ^ arm_insns[j].value) & decoded_insn->mask) & arm_insns[j].mask)) {
                panic(
                    HS_CORE,
                    "instruction \"%s\" collides with \"%s\".",
                    decoded_insn->name,
                    arm_insns[j].name
                );
            }
            ++j;
        }
#endif

        ++i;
    }
}