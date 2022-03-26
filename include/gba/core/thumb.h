/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#ifndef CORE_THUMB_H
# define CORE_THUMB_H

# include <stdint.h>
# include <unistd.h>

struct gba;

struct hs_thumb_insn {
    char const *name;
    char const *mask;
    void (*op)(struct gba *gba, uint16_t op);
};

struct hs_thumb_decoded_insn {
    uint16_t mask;
    uint16_t value;
};

extern void (*thumb_lut[256])(struct gba *gba, uint16_t op);

/* gba/thumb/alu.c */

void core_thumb_lo_add(struct gba *gba, uint16_t op);
void core_thumb_lo_sub(struct gba *gba, uint16_t op);
void core_thumb_mov_imm(struct gba *gba, uint16_t op);
void core_thumb_cmp_imm(struct gba *gba, uint16_t op);
void core_thumb_add_imm(struct gba *gba, uint16_t op);
void core_thumb_sub_imm(struct gba *gba, uint16_t op);
void core_thumb_hi_add(struct gba *gba, uint16_t op);
void core_thumb_hi_cmp(struct gba *gba, uint16_t op);
void core_thumb_hi_mov(struct gba *gba, uint16_t op);
void core_thumb_add_sp_imm(struct gba *gba, uint16_t op);
void core_thumb_add_pc_imm(struct gba *gba, uint16_t op);
void core_thumb_add_sp_s_imm(struct gba *gba, uint16_t op);
void core_thumb_alu(struct gba *gba, uint16_t op);

/* gba/thumb/branch.c */
void core_thumb_branch(struct gba *gba, uint16_t op);
void core_thumb_branch_link(struct gba *gba, uint16_t op);
void core_thumb_branch_xchg(struct gba *gba, uint16_t op);
void core_thumb_branch_cond(struct gba *gba, uint16_t op);

/* gba/thumb/gba.c */
void core_thumb_decode_insns(void);

/* gba/thumb/logical.c */
void core_thumb_lsl(struct gba *gba, uint16_t op);
void core_thumb_lsr(struct gba *gba, uint16_t op);
void core_thumb_asr(struct gba *gba, uint16_t op);

/* gba/thumb/sdt.c */
void core_thumb_push(struct gba *gba, uint16_t op);
void core_thumb_pop(struct gba *gba, uint16_t op);
void core_thumb_ldmia(struct gba *gba, uint16_t op);
void core_thumb_stmia(struct gba *gba, uint16_t op);
void core_thumb_sdt_imm(struct gba *gba, uint16_t op);
void core_thumb_sdt_h_imm(struct gba *gba, uint16_t op);
void core_thumb_sdt_wb_reg(struct gba *gba, uint16_t op);
void core_thumb_sdt_sbh_reg(struct gba *gba, uint16_t op);
void core_thumb_ldr_pc(struct gba *gba, uint16_t op);
void core_thumb_sdt_sp(struct gba *gba, uint16_t op);

/* gba/thumb/swi.c */
void core_thumb_swi(struct gba *gba, uint16_t op);

#endif /* !CORE_THUMB_H */