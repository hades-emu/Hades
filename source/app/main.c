/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <SDL2/SDL.h>
#include <GL/glew.h>
#include <cimgui.h>
#include <cimgui_impl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "hades.h"
#include "gba/gba.h"
#include "app/app.h"
#include "compat.h"

#ifdef WITH_DEBUGGER
# include "app/dbg.h"

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
    app.emulation.gba = gba_create();

    /* Default value for all options, before config and argument parsing. */
    app.run = true;
    app.args.with_gui = true;
    app.emulation.is_started = false;
    app.emulation.is_running = false;
    app.emulation.speed = 1;
    app.emulation.unbounded = false;
    app.emulation.backup_storage.autodetect = true;
    app.emulation.backup_storage.type = BACKUP_NONE;
    app.emulation.rtc.autodetect = true;
    app.emulation.rtc.enabled = true;
    app.file.bios_path = strdup("./bios.bin");
    app.video.color_correction = true;
    app.video.vsync = false;
    app.video.display_size = 3;
    app.video.aspect_ratio = ASPECT_RATIO_RESIZE;
    app.audio.mute = false;
    app.audio.level = 1.0f;
    app.audio.resample_frequency = 48000;
    app.gfx.texture_filter = TEXTURE_FILTER_NEAREST;
    app.ui.win.resize = true;
    app.ui.win.resize_with_ratio = false;

    app_paths_update(&app);
    app_args_parse(&app, argc, argv);
    app_bindings_setup_default(&app);
    app_config_load(&app);

    logln(HS_INFO, "Welcome to Hades v" HADES_VERSION);
    logln(HS_INFO, "=========================");

    if (app.args.with_gui) {
        app_sdl_init(&app);

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
    }

    /* Start the gba thread */
    pthread_create(
        &gba_thread,
        NULL,
        (void *(*)(void *))gba_run,
        app.emulation.gba
    );

    if (app.args.rom_path) {
        app_emulator_configure(&app, app.args.rom_path);
        if (app.emulation.launch_config) {
#ifdef WITH_DEBUGGER
            app_emulator_pause(&app);
#else
            app_emulator_run(&app);
#endif
        }
    }

#ifdef WITH_DEBUGGER
    signal(SIGINT, &sighandler);

    /* Start the debugger thread */
    pthread_create(
        &dbg_thread,
        NULL,
        (void *(*)(void *))debugger_run,
        &app
    );
#endif

    while (app.run) {
        uint64_t sdl_counters[2];
        float elapsed_ms;

        sdl_counters[0] = SDL_GetPerformanceCounter();

        app_emulator_process_all_notifs(&app);

#if WITH_DEBUGGER
        if (g_force_interrupt) {
            g_force_interrupt = false;
            app_emulator_pause(&app);
        }
#endif

        /*
        ** When used with a debugger, Hades can run without a GUI.
        ** This is mostly useful for the CI and automated testing.
        */
        if (!app.args.with_gui) {
            continue;
        }

        app_sdl_handle_events(&app);
        app_sdl_video_render_frame(&app);

        if (app.emulation.is_started && app.emulation.is_running) {
            uint32_t now;

            now = SDL_GetTicks();
            if ((now - app.ui.ticks_last_frame) >= 1000) {
                app.emulation.fps = gba_shared_reset_frame_counter(app.emulation.gba);
                app.ui.ticks_last_frame = now;

                /*
                ** We also want to store the content of the backup storage
                ** on the disk every second (if it is dirty).
                */
                app_emulator_update_backup(&app);

                /*
                ** We also update the Window's name with the game title
                */
                if (app.emulation.game_entry) {
                    SDL_SetWindowTitle(app.sdl.window, app.emulation.game_entry->title);
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

        /*
        ** Handle the power-save mode.
        **
        ** Required because imgui uses quite a lot of CPU even when nothing is happening.
        */
        if (app.emulation.is_started && app.emulation.is_running) {
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

        // Flush the quick save cache
        if (app.file.flush_qsaves_cache) {
            size_t i;

            for (i = 0; i < MAX_QUICKSAVES; ++i) {
                free(app.file.qsaves[i].mtime);
                app.file.qsaves[i].exist = hs_fexists(app.file.qsaves[i].path);
                app.file.qsaves[i].mtime = hs_fmtime(app.file.qsaves[i].path);
                app.file.flush_qsaves_cache = false;
            }

            app.file.flush_qsaves_cache = false;
        }
    }

    app_emulator_exit(&app);
    pthread_join(gba_thread, NULL);

#ifdef WITH_DEBUGGER
    debugger_reset_terminal();
#endif

    if (app.args.with_gui) {
        app_sdl_cleanup(&app);
    }

    app_config_save(&app);

    gba_delete(app.emulation.gba);
    app.emulation.gba = NULL;

    return (EXIT_SUCCESS);
}
