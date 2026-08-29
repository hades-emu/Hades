/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include "gba/cheat.h"
#include "gba/debugger.h"
#include "gba/memory.h"

static const uint32_t S0 = 0x7AA9648F;
static const uint32_t S1 = 0x7FAE6994;
static const uint32_t S2 = 0xC0EFAAD5;
static const uint32_t S3 = 0x42712C57;

// Reference:
//   - http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
static
void
cheat_parv3_decrypt_cheat(
    uint32_t *op1,
    uint32_t *op2
) {

    uint32_t i;
    uint32_t sum;

    sum = 0xC6EF3720;
    for (i = 0; i < 32; ++i) {
        *op2 -= (*op1 * 16 + S2) ^ (*op1 + sum) ^ (*op1 / 32 + S3);
        *op1 -= (*op2 * 16 + S0) ^ (*op2 + sum) ^ (*op2 / 32 + S1);
        sum -= 0x9E3779B9;
    }
}

static
bool
cheat_parv3_try_fetch_next_op_pair(
    struct cheat_token **token,
    uint32_t *op1,
    uint32_t *op2
) {
    struct cheat_token *tok1;
    struct cheat_token *tok2;

    if (
        !*token ||
        !(*token)->next ||
        (*token)->kind != CHEAT_TOKEN_KIND_U32 ||
        (*token)->next->kind != CHEAT_TOKEN_KIND_U32
    ) {
        return false;
    }

    tok1 = *token;
    tok2 = tok1->next;

    *op1 = tok1->value.u32;
    *op2 = tok2->value.u32;

    cheat_parv3_decrypt_cheat(op1, op2);

    *token = tok2->next;
    return true;
}

static
uint32_t
cheat_parv3_parse_addr(
    uint32_t addr
) {
    return (((addr & 0x00F00000) << 4) | (addr & 0xFFFFF));
}

bool
cheat_parv3_compile(
    struct cheat_bin *bin,
    struct cheat_compiler *compiler
) {
    struct cheat_token *token;
    uint32_t op1;
    uint32_t op2;

    dbgln(HS_CHEAT, "Compiling a new PARV3 cheat");

    token = compiler->tokens;

    while (cheat_parv3_try_fetch_next_op_pair(&token, &op1, &op2)) {
        dbgln(HS_CHEAT, "  [%08x] [%08x]", op1, op2);

        if (op2 == 0x001DC0DE) {
            continue;
        }

        if (op1 != 0) {
            switch (op1 >> 24) {
                case 0xC4: { // Hook routine
                    if (bin->hook.active) {
                        break;
                    }

                    bin->hook.active = true;
                    bin->hook.bp.ptr = CART_0_START | (op1 & 0x00FFFFFF);
                    bin->hook.bp.thumb = true;
                    dbgln(HS_CHEAT, "    > Hook routine set to %08x", bin->hook.bp.ptr);
                    break;
                }
                case 0x00: {
                    struct cheat_insn *insn;

                    insn = cheat_create_insn(bin);
                    insn->kind = CHEAT_INSN_ASSIGN;
                    insn->width = 1;
                    insn->addr = cheat_parv3_parse_addr(op1);
                    insn->value = op2 & 0xFF;
                    insn->repeat = op2 >> 8;
                    break;
                }
                case 0x02: {
                    struct cheat_insn *insn;

                    insn = cheat_create_insn(bin);
                    insn->kind = CHEAT_INSN_ASSIGN;
                    insn->width = 2;
                    insn->addr = cheat_parv3_parse_addr(op1);
                    insn->value = op2 & 0xFFFF;
                    insn->repeat = (op2 >> 16) * 2;
                    break;
                }
                case 0x04: {
                    struct cheat_insn *insn;

                    insn = cheat_create_insn(bin);
                    insn->kind = CHEAT_INSN_ASSIGN;
                    insn->width = 4;
                    insn->addr = cheat_parv3_parse_addr(op1);
                    insn->value = op2;
                    insn->repeat = 0;
                    break;
                }
                default: {
                    compiler->error = hs_format("Unknown, invalid or unsupported instruction %08x %08x", op1, op2);
                    return false;
                }
            };
        } else {
            switch (op2 >> 24) {
                case 0x18:
                case 0x1A:
                case 0x1C:
                case 0x1E: { // ROM Patch
                    uint32_t val1;
                    uint32_t val2;
                    uint32_t addr;

                    addr = CART_0_START + (op2 & 0xFFFFFF) * 2;

                    if (!cheat_parv3_try_fetch_next_op_pair(&token, &val1, &val2)) {
                        compiler->error = hs_format("Invalid or missing ROM Patch value");
                        return false;
                    }

                    cheat_create_rom_patch(
                        bin,
                        addr,
                        val1,
                        2
                    );

                    break;
                };
                default: {
                    compiler->error = hs_format("Unknown, invalid or unsupported instruction %08x %08x", op1, op2);
                    return false;
                };
            }
        }
    }

    if (token) {
        compiler->error = hs_format("Invalid or incomplete instruction");
        return false;
    }

    dbgln(HS_CHEAT, "Done");
    return true;
}
