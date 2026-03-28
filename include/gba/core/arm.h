/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#pragma once

#include <stdint.h>
#include <unistd.h>

struct gba;

struct hs_arm_insn {
    char const *name;
    char const *mask;
    void (*op)(struct gba *gba, uint32_t op);
};

struct hs_arm_decoded_insn {
    uint32_t mask;
    uint32_t value;
};

extern void (*arm_lut[4096])(struct gba *gba, uint32_t op);
extern bool cond_lut[256];

/* core/arm/alu.c */
void core_arm_alu(struct gba *gba, uint32_t op);

/* core/arm/bdt.c */
void core_arm_bdt(struct gba *gba, uint32_t op);

/* core/arm/branch.c */
void core_arm_branch(struct gba *gba, uint32_t op);
void core_arm_branch_xchg(struct gba *gba, uint32_t op);

/* core/arm/core.c */
void core_arm_decode_insns(void);

/* core/arm/mul.c */
void core_arm_mul(struct gba *gba, uint32_t op);
void core_arm_mull(struct gba *gba, uint32_t op);

/* core/arm/psr.c */
void core_arm_mrs(struct gba *gba, uint32_t op);
void core_arm_msr(struct gba *gba, uint32_t op);

/* core/arm/sdt.c */
void core_arm_sdt(struct gba *gba, uint32_t op);
void core_arm_hsdt(struct gba *gba, uint32_t op);

/* core/arm/swi.c */
void core_arm_swi(struct gba *gba, uint32_t op);

/* core/arm/swp.c */
void core_arm_swp(struct gba *gba, uint32_t op);
