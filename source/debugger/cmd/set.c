/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "debugger.h"
#include "gba.h"

void
debugger_cmd_set(
    struct gba *gba,
    size_t argc __unused,
    char const * const *argv
) {
    struct core *core;
    char const *reg_name;
    uint32_t reg_value;
    struct register_alias *alias;

    core = &gba->core;
    reg_name = argv[1];
    reg_value = debugger_eval_expr(gba, argv[2]);

    alias = register_alias_list;
    while (alias->name) {
        if (!strcmp(alias->name, reg_name)) {
            switch (alias->idx) {
                case REGISTER_R0 ... REGISTER_R14:
                    core->registers[alias->idx] = reg_value;
                    break;
                case REGISTER_R15:
                    core->pc = reg_value;
                    core_reload_pipeline(gba);
                    break;
                case REGISTER_CPSR:
                    continue;
            }
            printf("%s set to 0x%08x.\n", reg_name, reg_value);
            return ;
        }
        ++alias;
    }

    printf("Register %s doesn't exist.\n", reg_name);
}
