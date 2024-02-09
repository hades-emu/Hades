/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "app/app.h"
#include "compat.h"

void
app_paths_update(
    struct app *app
) {
    char *sys_config_dir;
    char *sys_pictures_dir;

    sys_config_dir = hs_system_config_dir();
    sys_pictures_dir = hs_system_pictures_dir();

    if (sys_config_dir && hs_fexists(sys_config_dir)) {
        char *hades_config_dir;

        asprintf(&hades_config_dir, "%s/Hades", sys_config_dir);
        hs_assert(hades_config_dir);

        if (!hs_fexists(hades_config_dir)) {
            hs_mkdir(hades_config_dir);
        }

        asprintf(&app->file.sys_config_path, "%s/config.json", hades_config_dir);

        free(hades_config_dir);
        free(sys_config_dir);
    }

    if (sys_pictures_dir && hs_fexists(sys_pictures_dir)) {
        asprintf(&app->file.sys_pictures_dir_path, "%s/Hades", sys_pictures_dir);
        hs_assert(app->file.sys_pictures_dir_path);

        free(sys_pictures_dir);
    }
}

char const *
app_path_config(
    struct app *app
) {
    if (app->args.config_path) {
        return (app->args.config_path);
    }

    if (hs_fexists("./config.json")) {
        return ("./config.json");
    }

    if (app->file.sys_config_path) {
        return (app->file.sys_config_path);
    }

    return ("./config.json");
}

char const *
app_path_screenshots(
    struct app *app
) {
    return (app->file.sys_pictures_dir_path ?: "screeenshots");
}
