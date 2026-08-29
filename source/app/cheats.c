/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <errno.h>
#include <mjson.h>
#include "app/app.h"
#include "compat.h"

static
int
app_emulator_grow_mjson_buffer(
    const char *in_buffer,
    int in_len,
    void *data
) {
    char **out_buffer;
    size_t out_len;

    out_buffer = (char **)data;

    out_len = *out_buffer ? strlen(*out_buffer) : 0;
    *out_buffer = realloc(*out_buffer, out_len + in_len + 1);
    memcpy(*out_buffer + out_len, in_buffer, in_len);
    (*out_buffer)[out_len + in_len] = '\0';

    return in_len;
}

void
app_cheats_load(
    struct app *app,
    char const *rom_path
) {
    FILE *file;
    char *path;
    char *data;
    size_t data_len;
    int off;
    int koff;
    int klen;
    int voff;
    int vlen;
    int vtype;

    free(app->cheats.list);
    app->cheats.len = 0;

    path = app_path_cheats(app, rom_path);
    if (!hs_fexists(path)) {
        logln(HS_INFO, "No cheats found for this game.");
        return;
    }

    logln(HS_INFO, "Using cheats at \"%s%s%s\".", g_light_green, path, g_reset);

    file = hs_fopen(path, "r");
    if (!file) {
        logln(HS_ERROR, "Failed to open \"%s\": %s", path, strerror(errno));
        return;
    }

    fseek(file, 0, SEEK_END);
    data_len = ftell(file);
    rewind(file);

    data = calloc(1, data_len);
    hs_assert(data);

    if (fread(data, 1, data_len, file) != data_len) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "Failed to read %s: %s.",
            path,
            strerror(errno)
        );
        goto end;
    }

    for (off = 0; (off = mjson_next(data, strlen(data), off, &koff, &klen, &voff, &vlen, &vtype));) {
        struct gba_cheat_raw *cheat;
        double d;
        int i;

        app->cheats.len += 1;
        app->cheats.list = realloc(app->cheats.list, app->cheats.len * sizeof(struct gba_cheat_raw));
        hs_assert(app->cheats.list);

        cheat = &app->cheats.list[app->cheats.len - 1];
        memset(cheat, 0, sizeof(struct gba_cheat_raw));

        mjson_get_bool(data + voff, vlen, "$.enabled", &i);
        cheat->enabled = (bool)i;

        mjson_get_number(data + voff, vlen, "$.kind", &d);
        cheat->kind = (int)d;

        mjson_get_string(data + voff, vlen, "$.name", cheat->name, sizeof(cheat->name));
        mjson_get_string(data + voff, vlen, "$.code", cheat->code, sizeof(cheat->code));
    }

    logln(HS_INFO, "Cheats file successfully read.");

end:
    free(data);
    fclose(file);
}

void
app_cheats_save(
    struct app const *app
) {
    FILE *file;
    char *data;
    char *path;
    char *pretty_data;
    size_t i;
    int out;

    if (!app->emulation.is_started || !app->emulation.game_path) {
        logln(HS_ERROR, "Attempted to save cheats when no game is running.");
        return;
    }

    data = NULL;
    pretty_data = NULL;
    path = app_path_cheats(app, app->emulation.game_path);

    if (app->cheats.len <= 0) {
        hs_remove(path);
        return;
    }

    file = hs_fopen(path, "w");
    if (!file) {
        logln(HS_ERROR, "Failed to open \"%s\": %s", path, strerror(errno));
        return;
    }

    mjson_printf(app_emulator_grow_mjson_buffer, &data, "[");
    for (i = 0; i < app->cheats.len; ++i) {
        if (i > 0) {
            mjson_printf(app_emulator_grow_mjson_buffer, &data, ",");
        }

        mjson_printf(
            app_emulator_grow_mjson_buffer,
            &data,
            STR({
                "kind": %d,
                "enabled": %B,
                "name": %Q,
                "code": %Q
            }),
            app->cheats.list[i].kind,
            (int)app->cheats.list[i].enabled,
            app->cheats.list[i].name,
            app->cheats.list[i].code
        );
    }
    mjson_printf(app_emulator_grow_mjson_buffer, &data, "]");

    out = mjson_pretty(data, strlen(data), "  ", mjson_print_dynamic_buf, &pretty_data);

    if (out < 0) {
        logln(HS_ERROR, "Failed to write the cheats to \"%s\": the formatted JSON is invalid.", path);
        goto end;
    }

    if (fwrite(pretty_data, strlen(pretty_data), 1, file) != 1) {
        logln(HS_ERROR, "Failed to write the configuration to \"%s\": %s.", path, strerror(errno));
    }

    logln(HS_INFO, "Cheats saved to \"%s%s%s\".", g_light_green, path, g_reset);

end:
    free(data);
    free(pretty_data);
    fclose(file);
}
