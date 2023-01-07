/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <GL/glew.h>

#include <cimgui.h>
#include <cimgui_impl.h>

#define SDL_MAIN_HANDLED
#include <SDL2/SDL.h>

#ifdef _MSC_VER
# include <windows.h>
#endif

#include <pthread.h>
#include <signal.h>
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
#include "app.h"
#include "compat.h"
#include "gba/gba.h"
#include "gba/db.h"
#include "gui/gui.h"

#ifdef WITH_DEBUGGER
# include "dbg/dbg.h"

static atomic_bool g_force_interrupt = false;

/*
** The signal handler, used to set `g_force_interrupt` to true and go back to
** the debugger.
*/
static
void
sighandler(
    int signal
) {
    g_force_interrupt = true;
}

#endif


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
#ifdef WITH_DEBUGGER
    pthread_t dbg_thread;
#endif

    memset(&app, 0, sizeof(app));
    app.emulation.gba = calloc(1, sizeof(*app.emulation.gba));
    hs_assert(app.emulation.gba);
    gba_init(app.emulation.gba);

    /* Default value for all options, before config and argument parsing. */
    app.run = true;
    app.file.bios_path = strdup("./bios.bin");
    app.file.config_path = strdup("./config.json");
    app.emulation.started = false;
    app.emulation.running = false;
    app.emulation.speed = 1;
    app.emulation.unbounded = false;
    app.emulation.backup_type = BACKUP_AUTO_DETECT;
    app.emulation.rtc_autodetect = true;
    app.emulation.rtc_force_enabled = true;
    app.video.color_correction = true;
    app.video.vsync = false;
    app.video.display_size = 3;
    app.video.aspect_ratio = ASPECT_RATIO_RESIZE;
    app.audio.mute = false;
    app.audio.level = 1.0f;
    app.video.texture_filter.kind = TEXTURE_FILTER_NEAREST;
    app.video.texture_filter.refresh = true;
    app.ui.win.resize = true;
    app.ui.win.resize_ratio = 3;
    gui_sdl_setup_default_binds(&app);

    gui_config_load(&app);

    args_parse(&app, argc, argv);

    gui_sdl_init(&app);

    logln(HS_INFO, "Welcome to Hades v" HADES_VERSION);
    logln(HS_INFO, "=========================");
    logln(HS_INFO, "Opengl version: %s%s%s.", g_light_magenta, (char*)glGetString(GL_VERSION), g_reset);
    logln(
        HS_INFO,
        "Dpi: %s%.1f%s, Scale factor: %s%u%s, Refresh Rate: %s%uHz%s.",
        g_light_magenta,
        app.ui.dpi,
        g_reset,
        g_light_magenta,
        app.ui.scale,
        g_reset,
        g_light_magenta,
        app.ui.refresh_rate,
        g_reset
    );

    /* Start the gba thread */
    pthread_create(
        &gba_thread,
        NULL,
        (void *(*)(void *))gba_main_loop,
        app.emulation.gba
    );

#ifdef WITH_DEBUGGER
    signal(SIGINT, &sighandler);

    app_game_stop(&app);
    if (app.file.game_path) {
        app_game_reset(&app);
        app_game_pause(&app);
    }

    /* Start the debugger thread */
    pthread_create(
        &dbg_thread,
        NULL,
        (void *(*)(void *))debugger_run,
        &app
    );
#else
    app_game_stop(&app);
    if (app.file.game_path) {
        app_game_reset(&app);
        app_game_run(&app);
    }
#endif

    while (app.run) {
        uint64_t sdl_counters[2];
        float elapsed_ms;

        sdl_counters[0] = SDL_GetPerformanceCounter();

        gui_sdl_handle_inputs(&app);
        gui_sdl_video_render_frame(&app);

#if WITH_DEBUGGER
        if (g_force_interrupt) {
            g_force_interrupt = false;
            app_game_pause(&app);
        }
#endif

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
                app_game_write_backup(&app);

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

        /* The window needs to be resized */
        if (app.ui.win.resize) {
            uint32_t new_width;
            uint32_t new_height;

            /*
            ** Do we wanna resize it to the aspect ratio given in `app.ui.win.resize_ratio`?
            ** Otherwise, use `app.video.display_size`.
            */
            if (app.ui.win.resize_with_ratio) {
                new_width = GBA_SCREEN_WIDTH * app.ui.win.resize_ratio * app.ui.scale;
                new_height = app.ui.menubar_size.y + GBA_SCREEN_HEIGHT * app.ui.win.resize_ratio * app.ui.scale;
            } else {
                new_width = GBA_SCREEN_WIDTH * app.video.display_size * app.ui.scale;
                new_height = app.ui.menubar_size.y + GBA_SCREEN_HEIGHT * app.video.display_size * app.ui.scale;
            }

            SDL_SetWindowMinimumSize(app.sdl.window, GBA_SCREEN_WIDTH * app.ui.scale, app.ui.menubar_size.y + GBA_SCREEN_HEIGHT * app.ui.scale);
            SDL_SetWindowSize(app.sdl.window, new_width, new_height);
            app.ui.win.resize = false;
            app.ui.win.resize_with_ratio = false;
        }

        sdl_counters[1] = SDL_GetPerformanceCounter();
        elapsed_ms = ((float)(sdl_counters[1] - sdl_counters[0]) / (float)SDL_GetPerformanceFrequency()) * 1000.f;

        if (app.emulation.started && app.emulation.running) {
            // If the emulator is running without vsync, cap the gui's FPS to 4x the display's refresh rate
            if (!app.video.vsync) {
                SDL_Delay(max(0.f, floor((1000.f / (4.0 * app.ui.refresh_rate)) - elapsed_ms)));
            }

            app.ui.power_save_fcounter = POWER_SAVE_FRAME_DELAY;
        } else {
            bool use_power_save_mode;

            use_power_save_mode = !igGetHoveredID();

            if (use_power_save_mode) {
                app.ui.power_save_fcounter -= !!(app.ui.power_save_fcounter);
                use_power_save_mode = !(app.ui.power_save_fcounter);
            } else {
                app.ui.power_save_fcounter = POWER_SAVE_FRAME_DELAY;
            }

            if (use_power_save_mode) {
                SDL_Delay(max(0.f, floor((1000.f / 15.0f) - elapsed_ms)));
            } else {
                SDL_Delay(max(0.f, floor((1000.f / 60.0f) - elapsed_ms)));
            }
        }
    }

    gba_send_exit(app.emulation.gba);
    pthread_join(gba_thread, NULL);

#ifdef WITH_DEBUGGER
    debugger_reset_terminal();
#endif

    gui_sdl_cleanup(&app);

    gui_config_save(&app);

    return (EXIT_SUCCESS);
}
