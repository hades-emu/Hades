/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#define SDL_MAIN_USE_CALLBACKS
#include <SDL3/SDL_main.h>
#include <stdlib.h>
#include <signal.h>
#include <math.h>
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

SDL_AppResult
SDL_AppInit(
    void **appstate,
    int argc,
    char **argv
) {
    struct app *app;
    SDL_AppResult res;

    app = calloc(1, sizeof(struct app));
    *appstate = app;

    app->emulation.gba = gba_create();
    app->run = true;
    app->audio.resample_frequency = 48000;
    app->ui.menubar.visibility = 1.0f;

    app_config_default_settings(app);
    app_config_default_bindings(app);
    app_paths_update(app);

    // Parse arguments
    res = app_args_parse(app, argc, argv);
    if (res != SDL_APP_CONTINUE) {
        return res;
    }

    app_config_load(app);

    logln(HS_INFO, "Welcome to Hades v" HADES_VERSION);
    logln(HS_INFO, "=========================");
    logln(HS_INFO, "Using configuration file \"%s%s%s\".", g_light_green, app_path_config(app), g_reset);

    if (!app->args.without_gui) {

#if defined(__linux__)
        // On Linux, hint at SDL that we are using Wayland if WAYLAND_DISPLAY is set.
        if (getenv("WAYLAND_DISPLAY")) {
            SDL_SetHint(SDL_HINT_VIDEO_DRIVER, "wayland");
        }
#endif

        if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMEPAD | SDL_INIT_AUDIO)) {
            logln(HS_ERROR, "Failed to init the SDL: %s", SDL_GetError());
            return SDL_APP_FAILURE;
        }

        app_sdl_audio_init(app);
        app_sdl_video_init(app);

        logln(HS_INFO, "Opengl version: %s%s%s.", g_light_magenta, (char*)glGetString(GL_VERSION), g_reset);
        logln(HS_INFO, "Scale factor: %s%.2f%s", g_light_magenta, app->ui.display_content_scale, g_reset);
    }

    // Start the gba thread
    pthread_create(
        &app->threads.gba,
        NULL,
        (void *(*)(void *))gba_run,
        app->emulation.gba
    );

    if (app->args.rom_path) {
        // Start the game provided in arguments
        app_emulator_configure_and_run(app, app->args.rom_path, NULL);
    } else if (
           app->settings.general.startup.start_last_played_game
        && app->file.recent_roms[0]
        && strlen(app->file.recent_roms[0])
    ) {
        // Start the last played game
        app_emulator_configure_and_run(app, app->file.recent_roms[0], NULL);
    }

#ifdef WITH_DEBUGGER
    signal(SIGINT, &sighandler);

    // Start the debugger thread
    pthread_create(
        &app->threads.dbg,
        NULL,
        (void *(*)(void *))debugger_run,
        app
    );
#endif

    // Set the initial value of the performance counters, used for FPS calculations
    app->sdl.counters[0] = SDL_GetPerformanceCounter();
    app->sdl.counters[1] = app->sdl.counters[0];

    return SDL_APP_CONTINUE;
}

SDL_AppResult
SDL_AppIterate(
    void *appstate
) {
    struct app *app;
    float elapsed_ms;

    app = appstate;

    app->sdl.counters[0] = app->sdl.counters[1];
    app->sdl.counters[1] = SDL_GetPerformanceCounter();
    elapsed_ms = ((float)(app->sdl.counters[1] - app->sdl.counters[0]) / (float)SDL_GetPerformanceFrequency()) * 1000.f;

    app_emulator_process_all_notifs(app);

#if WITH_DEBUGGER
    if (g_force_interrupt) {
        g_force_interrupt = false;
        app_emulator_pause(app);
    }
#endif

    // When used with a debugger, Hades can run without a GUI.
    // This is mostly useful for CI and automated testing.
    if (app->args.without_gui) {
        return app->run ? SDL_APP_CONTINUE : SDL_APP_SUCCESS;
    }

    app_sdl_video_render_frame(app);

    // Do all the stuff that must be done every second while the game is running.
    // Currently, this includes:
    //   - Updating the FPS counter
    //   - Synchronizing the save file on the disc
    if (app->emulation.is_started && app->emulation.is_running) {
        uint32_t now;

        now = SDL_GetTicks();
        if ((now - app->ui.ticks_last_frame) >= 1000) {
            app->emulation.fps = gba_shared_reset_frame_counter(app->emulation.gba) / (float)(now - app->ui.ticks_last_frame) * 1000.0;
            app->ui.ticks_last_frame = now;

            // We also want to store the content of the backup storage
            // on the disk every second (if it is dirty).
            app_emulator_write_save_to_disk(app);
        }
    }

    // Update the UI scale if needed
    // We do this here to avoid scaling the app in the middle of a frame.
    if (app->ui.request_scale_update) {
        app_sdl_video_update_scale(app);
        app->ui.request_scale_update = false;
    }

    // Handle all the stuff that must disappear after a few seconds if the mouse isn't moving
    // and the UI isn't being used.
    if (app->emulation.is_started && !igGetHoveredID() && !igGetFocusID() && !app->ui.settings.open) {
        if (app->ui.menubar.force_show) {
            app->ui.time_elapsed_since_last_mouse_motion_ms = 0.0f;
            app->ui.menubar.visibility = 1.0f;
            app->ui.menubar.force_show = false;
        } else if (app->ui.menubar.force_hide) {
            app->ui.time_elapsed_since_last_mouse_motion_ms = 1950.0f;
            app->ui.menubar.visibility = 1.0f;
            app->ui.menubar.force_hide = false;
        } else if (app->ui.time_elapsed_since_last_mouse_motion_ms <= 2000.0) {
            app->ui.time_elapsed_since_last_mouse_motion_ms += elapsed_ms;
        }

        // Hide the cursor if the mouse is inactive for a while
        if (app->settings.general.window.hide_cursor_when_mouse_inactive) {
            bool show_cursor;
            bool is_cursor_visible;

            is_cursor_visible = igGetMouseCursor() != ImGuiMouseCursor_None;
            show_cursor = (app->ui.time_elapsed_since_last_mouse_motion_ms < 2000.0);

            if (show_cursor != is_cursor_visible) {
                igSetMouseCursor(show_cursor ? ImGuiMouseCursor_Arrow : ImGuiMouseCursor_None);
            }
        }

        // Hide the menubar if the mouse is inactive for a while
        // We slowly change `visibility` to go from 1.0 to 0.0 over 50ms, after the mouse is inactive for 1950ms.
        if (app->settings.video.menubar_mode == MENUBAR_MODE_AUTO_HIDE) {
            if (app->ui.time_elapsed_since_last_mouse_motion_ms < 1950.0) {
                app->ui.menubar.visibility = 1.0f;
            } else if (app->ui.time_elapsed_since_last_mouse_motion_ms >= 1950.0 && app->ui.time_elapsed_since_last_mouse_motion_ms <= 2000.0) {
                app->ui.menubar.visibility = (2000.0 - app->ui.time_elapsed_since_last_mouse_motion_ms) / 50.0;
            } else {
                app->ui.menubar.visibility = 0.0f;
            }
        }
    } else {
        app->ui.time_elapsed_since_last_mouse_motion_ms = 0;

        if (igGetMouseCursor() == ImGuiMouseCursor_None) {
            igSetMouseCursor(ImGuiMouseCursor_Arrow);
        }

        app->ui.menubar.visibility = 1.0f;
        app->ui.menubar.force_hide = false;
        app->ui.menubar.force_show = false;
    }

    // Handle the power-save mode.
    // We do this because imgui uses quite a lot of CPU even when nothing is happening.
    // This allows us to have nearly 0% cpu usage when no game is running.
    if ((!app->emulation.is_started || !app->emulation.is_running)) {
        app->ui.power_save_fcounter -= !!(app->ui.power_save_fcounter);

        if (app->ui.power_save_fcounter <= 0) {
            SDL_Delay(1000.f / 15.0f); // ~15 fps on power save mode
        }
    } else {
        app->ui.power_save_fcounter = POWER_SAVE_FRAME_DELAY;
    }

    return app->run ? SDL_APP_CONTINUE : SDL_APP_SUCCESS;
}

SDL_AppResult
SDL_AppEvent(
    void *appstate,
    SDL_Event *event
) {
    struct app *app;

    app = appstate;

    app_sdl_handle_events(app, event);

    return app->run ? SDL_APP_CONTINUE : SDL_APP_SUCCESS;
}

void
SDL_AppQuit(
    void *appstate,
    SDL_AppResult result
) {
    struct app *app;

    app = appstate;

    app_emulator_exit(app);

    if (app->threads.gba) {
        pthread_join(app->threads.gba, NULL);
    }

#ifdef WITH_DEBUGGER
    debugger_reset_terminal();
#endif

    if (!app->args.without_gui && app->sdl.window) {
        app_sdl_video_cleanup(app);
        app_sdl_audio_cleanup(app);
    }

    app_config_save(app);

    gba_delete(app->emulation.gba);
    app->emulation.gba = NULL;

    free(app);
}
