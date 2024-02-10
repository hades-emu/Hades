/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include "app/app.h"
#include "app/lang.h"
#include "app/dbg.h"

void
debugger_lang_mut_variables_push(
    struct app *app,
    char const *name,
    uint32_t *ptr
) {
    app->debugger.variables = realloc(app->debugger.variables, sizeof(struct variable) * (app->debugger.variables_len + 1));
    hs_assert(app->debugger.variables);

    app->debugger.variables[app->debugger.variables_len].name = strdup(name);
    app->debugger.variables[app->debugger.variables_len].ptr = ptr;
    app->debugger.variables[app->debugger.variables_len].mutable = true;
    ++app->debugger.variables_len;
}

void
debugger_lang_const_variables_push(
    struct app *app,
    char const *name,
    uint32_t val
) {
    app->debugger.variables = realloc(app->debugger.variables, sizeof(struct variable) * (app->debugger.variables_len + 1));
    hs_assert(app->debugger.variables);

    app->debugger.variables[app->debugger.variables_len].name = strdup(name);
    app->debugger.variables[app->debugger.variables_len].val = val;
    app->debugger.variables[app->debugger.variables_len].mutable = false;
    ++app->debugger.variables_len;
}

struct variable *
debugger_lang_variables_lookup(
    struct app *app,
    char const *name
) {
    struct variable *v;

    for (v = app->debugger.variables; v < app->debugger.variables + app->debugger.variables_len; ++v) {
        if (!strcmp(v->name, name)) {
            return (v);
        }
    }

    return (NULL);
}
