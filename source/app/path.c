/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "app/app.h"
#include "compat.h"

/*
** Capitalize the name of the Hades folders on Windows and MacOS.
*/
#if (defined (_WIN32) && !defined (__CYGWIN__)) || defined(__APPLE__)
#define HADES_FOLDER_NAME "Hades"
#else
#define HADES_FOLDER_NAME "hades"
#endif

/*
** Return the platform-dependent configuration directory or NULL
** if the system doesn't have one.
**
** The returned value must be freed.
*/
static inline
char *
system_config_dir(
    void
) {
#if __APPLE__
    char *home_dir;

    home_dir = getenv("HOME");
    if (home_dir && hs_fexists(home_dir)) {
        return (hs_format("%s/Library/Application Support", home_dir));
    }

    return (NULL);
#elif __unix__
    char *xdg_config_dir;
    char *home_dir;

    xdg_config_dir = getenv("XDG_CONFIG_HOME");
    if (xdg_config_dir && hs_fexists(xdg_config_dir)) {
        return (strdup(xdg_config_dir));
    }

    home_dir = getenv("HOME");
    if (home_dir && hs_fexists(home_dir)) {
        return (hs_format("%s/.config", home_dir));
    }

    return (NULL);
#else
    return (NULL);
#endif
}

/*
** Return the platform-dependent pictures directory or NULL
** if the system doesn't have one.
**
** The returned value must be freed.
*/
static inline
char *
system_pictures_dir(
    void
) {
#if __APPLE__
    char *home_dir;

    home_dir = getenv("HOME");
    if (home_dir && hs_fexists(home_dir)) {
        return (hs_format("%s/Pictures", home_dir));
    }

    return (NULL);
#elif __unix__
    char *xdg_pictures_dir;
    char *home_dir;

    xdg_pictures_dir = getenv("XDG_PICTURES_DIR");
    if (xdg_pictures_dir && hs_fexists(xdg_pictures_dir)) {
        return (strdup(xdg_pictures_dir));
    }

    home_dir = getenv("HOME");
    if (home_dir && hs_fexists(home_dir)) {
        return (strdup(home_dir));
    }

    return (NULL);
#else
    return (NULL);
#endif
}

void
app_paths_update(
    struct app *app
) {
    char *sys_config_dir;
    char *sys_pictures_dir;

    sys_config_dir = system_config_dir();
    sys_pictures_dir = system_pictures_dir();

    if (sys_config_dir && hs_fexists(sys_config_dir)) {
        char *hades_config_dir;

        hades_config_dir = hs_format("%s/%s", sys_config_dir, HADES_FOLDER_NAME);

        if (!hs_fexists(hades_config_dir)) {
            hs_mkdir(hades_config_dir);
        }

        app->file.sys_config_path = hs_format("%s/config.json", hades_config_dir);

        free(hades_config_dir);
        free(sys_config_dir);
    }

    if (sys_pictures_dir && hs_fexists(sys_pictures_dir)) {
        app->file.sys_pictures_dir_path = hs_format("%s/%s", sys_pictures_dir, HADES_FOLDER_NAME);
        free(sys_pictures_dir);
    }
}

char const *
app_path_config(
    struct app const *app
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
    struct app const *app
) {
    if (!app->settings.general.directories.screenshot.use_system_directory && app->settings.general.directories.screenshot.path) {
        return (app->settings.general.directories.screenshot.path);
    }
    return app->file.sys_pictures_dir_path ?: "screenshots";
}

char *
app_path_backup(
    struct app const *app,
    char const *rom
) {
    char const *rom_basename;
    char const *rom_ext;
    size_t dirname_len;
    size_t basename_len;

    rom_basename = strrchr(rom, HS_PATH_SEPARATOR);

    // The path contains a '/'
    if (rom_basename) {
        dirname_len = rom_basename - rom;
        ++rom_basename; // Skip the '/' and point to the first char of the basename
    } else {
        dirname_len = 0;
        rom_basename = rom;
    }

    rom_ext = strrchr(rom_basename, '.');
    basename_len = rom_ext - rom_basename;

    if (app->settings.general.directories.backup.use_dedicated_directory) {
        if (!hs_fexists(app->settings.general.directories.backup.path)) {
            hs_mkdir(app->settings.general.directories.backup.path);
        }
        return hs_format("%s/%.*s.sav", app->settings.general.directories.backup.path, (int)basename_len, rom_basename);
    } else {
        return hs_format("%.*s/%.*s.sav", (int)dirname_len, rom, (int)basename_len, rom_basename);
    }
}

void
app_path_update_quicksave_paths(
    struct app *app,
    char const *rom
) {
    char const *dirname;
    char const *rom_basename;
    char const *rom_ext;
    size_t dirname_len;
    size_t basename_len;
    size_t i;

    rom_basename = strrchr(rom, HS_PATH_SEPARATOR);

    // The path contains a '/'
    if (rom_basename) {
        dirname_len = rom_basename - rom;
        ++rom_basename; // Skip the '/' and point to the first char of the basename
    } else {
        dirname_len = 0;
        rom_basename = rom;
    }

    rom_ext = strrchr(rom_basename, '.');
    basename_len = rom_ext - rom_basename;

    if (app->settings.general.directories.quicksave.use_dedicated_directory) {
        if (!hs_fexists(app->settings.general.directories.quicksave.path)) {
            hs_mkdir(app->settings.general.directories.quicksave.path);
        }
        dirname = app->settings.general.directories.quicksave.path;
        dirname_len = strlen(dirname);
    } else {
        dirname = rom;
    }

    for (i = 0; i < MAX_QUICKSAVES; ++i) {
        free(app->file.qsaves[i].path);
        free(app->file.qsaves[i].mtime);

        app->file.qsaves[i].mtime = NULL;
        app->file.qsaves[i].path = hs_format(
            "%.*s/%.*s.%zu.hds",
            (int)dirname_len,
            dirname,
            (int)basename_len,
            rom_basename,
            i + 1
        );
    }

    app->file.flush_qsaves_cache = true;
}
