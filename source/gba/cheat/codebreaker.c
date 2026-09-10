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

static
bool
cheat_codebreaker_try_fetch_next_op_pair(
    struct cheat_token **token,
    uint32_t *op1,
    uint16_t *op2
) {
    struct cheat_token *tok1;
    struct cheat_token *tok2;

    if (
        !*token ||
        !(*token)->next ||
        (*token)->kind != CHEAT_TOKEN_KIND_U32 ||
        (*token)->next->kind != CHEAT_TOKEN_KIND_U16
    ) {
        return false;
    }

    tok1 = *token;
    tok2 = tok1->next;

    *op1 = tok1->value.u32;
    *op2 = tok2->value.u16;

    *token = tok2->next;
    return true;
}

bool
cheat_codebreaker_compile(
    struct cheat_bin *bin,
    struct cheat_compiler *compiler
) {
    struct cheat_token *token;
    uint32_t op1;
    uint16_t op2;

    dbgln(HS_CHEAT, "  - Compiling (Codebreaker)");

    token = compiler->tokens;

    while (cheat_codebreaker_try_fetch_next_op_pair(&token, &op1, &op2)) {
        dbgln(HS_CHEAT, "    - [ %08x %04x ]", op1, op2);

        switch (op1 >> 28) {
            case 0x0: break; // Enable Code 1 (Ignored)
            case 0x1: { // Enable Code 2 - Hook routine
                // XXX: I'm very confused about what op2 is supposed to represent. Ignoring it for now.

                if (bin->hook.active) {
                    break;
                }

                bin->hook.active = true;
                bin->hook.bp.ptr = CART_0_START | (op1 & CART_MASK);
                bin->hook.bp.thumb = true;
                break;
            }
            case 0x2: { // OR Assign
                struct cheat_insn *insn;

                insn = cheat_create_insn(bin);
                insn->kind = CHEAT_INSN_OR_ASSIGN;
                insn->or_assign.addr = op1 & 0x0FFFFFFF;
                insn->or_assign.width = 2;
                insn->or_assign.value = op2 & 0xFFFF;
                break;
            }
            case 0x3: { // Assign (8-bit)
                struct cheat_insn *insn;

                insn = cheat_create_insn(bin);
                insn->kind = CHEAT_INSN_ASSIGN;
                insn->assign.addr = op1 & 0x0FFFFFFF;
                insn->assign.width = 1;
                insn->assign.value = op2 & 0xFF;
                break;
            }
            case 0x4: { // Fill
                struct cheat_insn *insn;
                uint32_t val1;
                uint16_t val2;


                if (!cheat_codebreaker_try_fetch_next_op_pair(&token, &val1, &val2)) {
                    compiler->error = hs_format("Invalid or missing Fill value");
                    return false;
                }

                dbgln(HS_CHEAT, "    - [ %08x %04x ]", val1, val2);

                insn = cheat_create_insn(bin);
                insn->kind = CHEAT_INSN_ASSIGN;
                insn->assign.addr = op1 & 0x0FFFFFFF;
                insn->assign.width = 2;
                insn->assign.value = op2;
                insn->assign.repeat = val1 & 0xFFFF;
                insn->assign.addr_offset = val2;
                insn->assign.value_offset = val1 >> 16;
                break;
            }
            case 0x5: { // Memwrite
                size_t len;
                uint32_t addr;

                addr = op1 & 0x0FFFFFFF;
                len = op2 * 2;
                while (len > 0) {
                    uint32_t val1;
                    uint16_t val2;
                    uint64_t vals;
                    size_t i;

                    if (!cheat_codebreaker_try_fetch_next_op_pair(&token, &val1, &val2)) {
                        compiler->error = hs_format("Invalid or missing Fill value");
                        return false;
                    }

                    dbgln(HS_CHEAT, "    - [ %08x %04x ]", val1, val2);

                    vals = ((uint64_t)val1 << 16) | (uint64_t)val2;

                    dbgln(HS_CHEAT, "TEST: %016llx", vals);

                    for (i = 0; i < 6 && len > 0; ++i) {
                        struct cheat_insn *insn;

                        insn = cheat_create_insn(bin);
                        insn->kind = CHEAT_INSN_ASSIGN;
                        insn->assign.addr = addr;
                        insn->assign.width = 1;
                        insn->assign.value = (vals >> (40 - 8 * i)) & 0xFF;

                        ++addr;
                        --len;
                    }
                }
                break;
            }
            case 0x6: { // AND Assign
                struct cheat_insn *insn;

                insn = cheat_create_insn(bin);
                insn->kind = CHEAT_INSN_AND_ASSIGN;
                insn->and_assign.addr = op1 & 0x0FFFFFFF;
                insn->and_assign.width = 2;
                insn->and_assign.value = op2 & 0xFFFF;
                break;
            }
            case 0x8: { // Assign (16-bit)
                struct cheat_insn *insn;

                insn = cheat_create_insn(bin);
                insn->kind = CHEAT_INSN_ASSIGN;
                insn->assign.addr = op1 & 0x0FFFFFFF;
                insn->assign.width = 2;
                insn->assign.value = op2;
                break;
            }
            case 0xE: { // ADD Assign
                struct cheat_insn *insn;

                insn = cheat_create_insn(bin);
                insn->kind = CHEAT_INSN_ADD_ASSIGN;
                insn->add_assign.addr = op1 & 0x0FFFFFFF;
                insn->add_assign.width = 2;
                insn->add_assign.value = op2 & 0xFFFF;
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
