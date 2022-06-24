/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <GL/glew.h>

#include <cimgui.h>
#include <cimgui_impl.h>
#include <nfd.h>

#define SDL_MAIN_HANDLED
#include <SDL2/SDL.h>

#ifdef _MSC_VER
# include <windows.h>
#endif

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#ifdef IMGUI_HAS_IMSTR
# define igBegin igBegin_Str
# define igSliderFloat igSliderFloat_Str
# define igCheckbox igCheckbox_Str
# define igColorEdit3 igColorEdit3_Str
# define igButton igButton_Str
#endif

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include "hades.h"
#include "gba/gba.h"
#include "gba/db.h"
#include "platform/gui/game.h"
#include "platform/gui/common.h"
#include "utils/fs.h"

/*
** Print the program's usage.
*/
static
void
print_usage(
    FILE *file,
    char const *name
) {
    fprintf(
        file,
        "Usage: %s [OPTION]... ROM\n"
        "\n"
        "Options:\n"
        "    -b, --bios=PATH                   path pointing to the bios dump (default: \"bios.bin\")\n"
        "        --color=[always|never|auto]   adjust color settings (default: auto)\n"
        "\n"
        "    -h, --help                        print this help and exit\n"
        "    -v, --version                     print the version information and exit\n"
        "",
        name
    );
}

/*
** Parse the given command line arguments.
*/
static
void
args_parse(
    struct app *app,
    int argc,
    char *argv[]
) {
    char const *name;
    uint32_t color;

    color = 0;
    name = argv[0];
    while (true) {
        int c;
        int option_index;

        enum cli_options {
            CLI_HELP = 0,
            CLI_VERSION,
            CLI_BIOS,
            CLI_COLOR,
        };

        static struct option long_options[] = {
            [CLI_HELP]      = { "help",         no_argument,        0,  0 },
            [CLI_VERSION]   = { "version",      no_argument,        0,  0 },
            [CLI_BIOS]      = { "bios",         required_argument,  0,  0 },
            [CLI_COLOR]     = { "color",        optional_argument,  0,  0 },
                              { 0,              0,                  0,  0 }
        };

        c = getopt_long(
            argc,
            argv,
            "hvb:",
            long_options,
            &option_index
        );

        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                switch (option_index) {
                    case CLI_HELP: // --help
                        print_usage(stdout, name);
                        exit(EXIT_SUCCESS);
                        break;
                    case CLI_VERSION: // --version
                        printf("Hades v" HADES_VERSION "\n");
                        exit(EXIT_SUCCESS);
                        break;
                    case CLI_BIOS: // --bios
                        free(app->file.bios_path);
                        app->file.bios_path = strdup(optarg);
                        break;
                    case CLI_COLOR: // --color
                        if (optarg) {
                            if (!strcmp(optarg, "auto")) {
                                color = 0;
                                break;
                            } else if (!strcmp(optarg, "never")) {
                                color = 1;
                                break;
                            } else if (!strcmp(optarg, "always")) {
                                color = 2;
                                break;
                            } else {
                                print_usage(stderr, name);
                                exit(EXIT_FAILURE);
                            }
                        } else {
                            color = 0;
                        }
                        break;
                    default:
                        print_usage(stderr, name);
                        exit(EXIT_FAILURE);
                        break;
                }
                break;
            case 'b':
                free(app->file.bios_path);
                app->file.bios_path = strdup(optarg);
                break;
            case 'h':
                print_usage(stdout, name);
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                printf("Hades v" HADES_VERSION "\n");
                exit(EXIT_SUCCESS);
                break;
            default:
                print_usage(stderr, name);
                exit(EXIT_FAILURE);
                break;
        }
    }

    switch (argc - optind) {
        case 0:
            break;
        case 1:
            app->file.game_path = strdup(argv[optind]);
            break;
        default:
            print_usage(stderr, name);
            exit(EXIT_FAILURE);
    }

    switch (color) {
        case 0:
            if (!hs_isatty(1)) {
                disable_colors();
            }
            break;
        case 1:
            disable_colors();
            break;
    }
}

int
main(
    int argc,
    char *argv[]
) {
    struct app app;
    pthread_t gba_thread;

    memset(&app, 0, sizeof(app));
    app.emulation.gba = calloc(1, sizeof(*app.emulation.gba));
    hs_assert(app.emulation.gba);
    gba_init(app.emulation.gba);

    /* Default value for all options, before config and argument parsing. */
    app.file.bios_path = strdup("./bios.bin");
    app.file.config_path = strdup("./config.json");
    app.emulation.running = false;
    app.emulation.started = false;
    app.emulation.speed = 1;
    app.emulation.unbounded = false;
    app.emulation.backup_type = BACKUP_AUTO_DETECT;
    app.emulation.rtc_autodetect = true;
    app.emulation.rtc_force_enabled = true;
    app.video.color_correction = true;
    app.video.vsync = false;
    app.video.display_size = 3;
    app.audio.mute = false;
    app.audio.level = 1.0f;
    app.ui.refresh_windows_size = true;

    gui_config_load(&app);

    args_parse(&app, argc, argv);

    gui_sdl_init(&app);

    logln(HS_GLOBAL, "Welcome to Hades v" HADES_VERSION);
    logln(HS_GLOBAL, "=========================");
    logln(HS_GLOBAL, "Opengl version: %s%s%s.", g_light_magenta, (char*)glGetString(GL_VERSION), g_reset);
    logln(
        HS_GLOBAL,
        "Dpi: %s%.1f%s, Scale factor: %s%u%s.",
        g_light_magenta,
        app.ui.dpi,
        g_reset,
        g_light_magenta,
        app.ui.scale,
        g_reset
    );

    /* Start the gba thread */
    pthread_create(
        &gba_thread,
        NULL,
        (void *(*)(void *))gba_main_loop,
        app.emulation.gba
    );

    /* If a game was supplied in the arguments, launch it now */
    if (app.file.game_path) {
        gui_game_reset(&app);
    }

    app.run = true;
    while (app.run) {
        gui_sdl_handle_inputs(&app);
        gui_sdl_video_render_frame(&app);

        if (app.emulation.started && app.emulation.running) {
            uint32_t now;

            now = SDL_GetTicks();
            if ((now - app.ui.ticks_last_frame) >= 1000) {
                app.emulation.fps = atomic_exchange(&app.emulation.gba->framecounter, 0);
                app.ui.ticks_last_frame = now;

                /*
                ** We also want to store the content of the backup storage
                ** on the disk every second (if it is dirty).
                */
                gui_game_write_backup(&app);

                /*
                ** We also update the Window's name with the game title
                */
                if (app.emulation.gba->game_entry) {
                    SDL_SetWindowTitle(app.sdl.window, app.emulation.gba->game_entry->title);
                } else {
                    SDL_SetWindowTitle(app.sdl.window, "Hades");
                }
            }
        }

        if (app.ui.refresh_windows_size) {
            SDL_SetWindowSize(
                app.sdl.window,
                GBA_SCREEN_WIDTH * app.video.display_size * app.ui.scale,
                app.ui.menubar_size.y + GBA_SCREEN_HEIGHT * app.video.display_size * app.ui.scale
            );
            app.ui.refresh_windows_size = false;
        }
    }

    gui_sdl_cleanup(&app);

    gui_config_save(&app);

    return (EXIT_SUCCESS);
}