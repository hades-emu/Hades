/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include "gba/cheat.h"
#include "gba/memory.h"

static const uint32_t S0 = 0x09F4FBBD;
static const uint32_t S1 = 0x9681884A;
static const uint32_t S2 = 0x352027E9;
static const uint32_t S3 = 0xF3DEE5A7;

// Reference:
//   - http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
static
void
cheat_gameshark_decrypt_cheat(
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
cheat_gameshark_try_fetch_next_op_pair(
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

    cheat_gameshark_decrypt_cheat(op1, op2);

    *token = tok2->next;
    return true;
}

bool
cheat_gameshark_compile(
    struct cheat_bin *bin,
    struct cheat_compiler *compiler
) {
    struct cheat_token *token;
    uint32_t op1;
    uint32_t op2;

    dbgln(HS_CHEAT, "  - Compiling (GameShark)");

    token = compiler->tokens;

    while (cheat_gameshark_try_fetch_next_op_pair(&token, &op1, &op2)) {
        uint32_t kind;

        dbgln(HS_CHEAT, "    - [ %08x %08x ]", op1, op2);

        if (op2 == 0x001DC0DE) { // Enable Code (Ignored)
            continue;
        }

        kind = op1 >> 28;
        switch (kind) {
            case 0x0:
            case 0x1:
            case 0x2: { // Assign
                struct cheat_insn *insn;
                uint32_t mask;

                mask = (1ull << (8 << kind)) - 1;
                insn = cheat_create_insn(bin);
                insn->kind = CHEAT_INSN_ASSIGN;
                insn->assign.addr = op1 & 0x0FFFFFFF;
                insn->assign.width = 1 << kind;
                insn->assign.value = op2 & mask;
                break;
            }
            case 0x3: { // While-assign
                uint16_t length;
                uint32_t value;
                size_t i;

                length = (op1 & 0xFFFF) - 1;
                value = op2;

                i = 0;
                while (i < length && cheat_gameshark_try_fetch_next_op_pair(&token, &op1, &op2)) {
                    size_t j;

                    dbgln(HS_CHEAT, "    - [ %08x %08x ]", op1, op2);

                    for (j = 0; j < 2; ++j) {
                        struct cheat_insn *insn;

                        if (i + j >= length) {
                            break;
                        }

                        insn = cheat_create_insn(bin);
                        insn->kind = CHEAT_INSN_ASSIGN;
                        insn->assign.addr = j ? op2 : op1;
                        insn->assign.width = 4;
                        insn->assign.value = value;
                    }
                }
                break;
            }
            case 0x6: { // ROM Patch
                uint32_t addr;

                addr = CART_0_START + (op1 & 0xFFFFFF) * 2;

                cheat_create_rom_patch(
                    bin,
                    addr,
                    op2 & 0xFFFF,
                    2
                );
                break;
            }
            case 0xF: { // Hook routine
                if (bin->hook.active) {
                    break;
                }

                bin->hook.active = true;
                bin->hook.bp.ptr = op1 & 0x0FFFFFFF;
                bin->hook.bp.thumb = true;
                break;
            }
            default: {
                compiler->error = hs_format("Unknown, invalid or unsupported instruction %08x %08x", op1, op2);
                return false;
            }
        }
    }

    if (token) {
        compiler->error = hs_format("Invalid or incomplete instruction");
        return false;
    }

    dbgln(HS_CHEAT, "  - Compiled successfuly");
    return true;
}
