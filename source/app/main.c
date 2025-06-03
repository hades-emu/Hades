/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
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

/*
** Default value for all options, before config and argument parsing.
*/
static
void
app_settings_default(
    struct settings *settings
) {
    free(settings->emulation.bios_path);

    settings->general.show_fps = false;
    settings->general.start_last_played_game_on_startup = false;
    settings->general.pause_when_window_inactive = false;
    settings->general.pause_when_game_resets = false;
    settings->emulation.bios_path = strdup("./bios.bin");
    settings->emulation.skip_bios_intro = false;
    settings->emulation.speed = 1.0;
    settings->emulation.alt_speed = -1.0;
    settings->emulation.backup_storage.autodetect = true;
    settings->emulation.backup_storage.type = BACKUP_NONE;
    settings->emulation.gpio_device.autodetect = true;
    settings->emulation.gpio_device.type = GPIO_NONE;
    settings->emulation.prefetch_buffer = true;
    settings->video.enable_oam = true;
    memset(settings->video.enable_bg_layers, true, sizeof(settings->video.enable_bg_layers));
    memset(settings->audio.enable_psg_channels, true, sizeof(settings->audio.enable_psg_channels));
    memset(settings->audio.enable_fifo_channels, true, sizeof(settings->audio.enable_fifo_channels));
    settings->video.menubar_mode = MENUBAR_MODE_FIXED_ABOVE_GAME;
    settings->video.display_mode = DISPLAY_MODE_WINDOWED;
    settings->video.display_size = 3;
    settings->video.autodetect_scale = true;
    settings->video.scale = 1.0f;
    settings->video.aspect_ratio = ASPECT_RATIO_BORDERS;
    settings->video.vsync = false;
    settings->video.texture_filter = TEXTURE_FILTER_NEAREST;
    settings->video.pixel_color_filter = PIXEL_COLOR_FILTER_COLOR_CORRECTION;
    settings->video.pixel_scaling_filter = PIXEL_SCALING_FILTER_LCD_GRID;
    settings->video.hide_cursor_when_mouse_inactive = true;
    settings->video.use_system_screenshot_dir_path = true;
    settings->video.screenshot_dir_path = strdup("./screenshots/");
    settings->audio.mute = false;
    settings->audio.level = 1.0f;
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
    uint64_t sdl_counters[2];
    uint64_t last_rescale_recalculation_ms;

    memset(&app, 0, sizeof(app));
    app.emulation.gba = gba_create();

    app.run = true;
    app.args.with_gui = true;
    app.emulation.is_started = false;
    app.emulation.is_running = false;
    app.audio.resample_frequency = 48000;
    app.ui.menubar.visibility = 1.0f;
    app_settings_default(&app.settings);
    app_bindings_setup_default(&app);

    app_paths_update(&app);
    app_args_parse(&app, argc, argv);
    app_config_load(&app);

    logln(HS_INFO, "Welcome to Hades v" HADES_VERSION);
    logln(HS_INFO, "=========================");
    logln(HS_INFO, "Using configuration file \"%s%s%s\".", g_light_green, app_path_config(&app), g_reset);

    if (app.args.with_gui) {
        app_sdl_init(&app);

        logln(HS_INFO, "Opengl version: %s%s%s.", g_light_magenta, (char*)glGetString(GL_VERSION), g_reset);
        logln(
            HS_INFO,
            "Dpi: %s%.1f%s, Scale factor: %s%.2f%s, Refresh Rate: %s%uHz%s.",
            g_light_magenta,
            app.ui.display_dpi,
            g_reset,
            g_light_magenta,
            app.ui.scale,
            g_reset,
            g_light_magenta,
            app.ui.display_refresh_rate,
            g_reset
        );
    }

    // Start the gba thread
    pthread_create(
        &gba_thread,
        NULL,
        (void *(*)(void *))gba_run,
        app.emulation.gba
    );

    // Start the game provided in arguments
    if (app.args.rom_path) {
        app_emulator_configure_and_run(&app, app.args.rom_path, NULL);
    } else if ( // Start the last played game
           app.settings.general.start_last_played_game_on_startup
        && app.file.recent_roms[0]
        && strlen(app.file.recent_roms[0])
    ) {
        app_emulator_configure_and_run(&app, app.file.recent_roms[0], NULL);
    }

#ifdef WITH_DEBUGGER
    signal(SIGINT, &sighandler);

    // Start the debugger thread
    pthread_create(
        &dbg_thread,
        NULL,
        (void *(*)(void *))debugger_run,
        &app
    );
#endif

    sdl_counters[0] = SDL_GetPerformanceCounter();
    sdl_counters[1] = sdl_counters[0];

    while (app.run) {
        float elapsed_ms;

        sdl_counters[0] = sdl_counters[1];
        sdl_counters[1] = SDL_GetPerformanceCounter();

        app_emulator_process_all_notifs(&app);

#if WITH_DEBUGGER
        if (g_force_interrupt) {
            g_force_interrupt = false;
            app_emulator_pause(&app);
        }
#endif

        // When used with a debugger, Hades can run without a GUI.
        // This is mostly useful CI and automated testing.
        if (!app.args.with_gui) {
            continue;
        }

        app_sdl_handle_events(&app);
        app_sdl_video_render_frame(&app);

        // Update the FPS counter and the window's title.
        if (app.emulation.is_started && app.emulation.is_running) {
            uint32_t now;

            now = SDL_GetTicks();
            if ((now - app.ui.ticks_last_frame) >= 1000) {
                app.emulation.fps = gba_shared_reset_frame_counter(app.emulation.gba) / (float)(now - app.ui.ticks_last_frame) * 1000.0;
                app.ui.ticks_last_frame = now;

                // We also want to store the content of the backup storage
                // on the disk every second (if it is dirty).
                app_emulator_update_backup(&app);

                // We also update the Window's name with the game title
                if (app.emulation.game_entry && app.emulation.game_entry->title) {
                    SDL_SetWindowTitle(app.sdl.window, app.emulation.game_entry->title);
                } else {
                    SDL_SetWindowTitle(app.sdl.window, "Hades");
                }
            }
        }

        // Handle window resize request
        // There's a bug on Linux/Wayland that prevents us from resizing the window during
        // the first frame, hence why we wait in that case.
        if (app.ui.display.resize_request_timer && !--app.ui.display.resize_request_timer) {
            app_sdl_video_resize_window(&app);
        }

        // Recalculate the display scale every 100ms
        //
        // We do this periodically to avoid glitching when the window is in-between two monitors.
        // It might look like a weird idea, but overall this adds a lot of stability to the hidpi system.
        //
        // This also prevents us from calling `app_sdl_video_calculate_scale()` every frame, which
        // would be quite costly.
        last_rescale_recalculation_ms = (uint64_t)((float)sdl_counters[0] / (float)SDL_GetPerformanceFrequency() * 1000.f);
        if (last_rescale_recalculation_ms - app.ui.display.last_scale_calculation_ms > 100) {
            float display_scale;

            app.ui.display.last_scale_calculation_ms = last_rescale_recalculation_ms;
            display_scale = app_sdl_video_calculate_scale(&app);

            // If the scale changed significantly
            if (display_scale - app.ui.display_scale > 0.01 || display_scale - app.ui.display_scale < -0.01) {
                app.ui.display_scale = display_scale;
                app.ui.request_scale_update |= app.settings.video.autodetect_scale;

                // Request a resize to ensure the window matches the new scale
                app.ui.display.resize_request_timer = DEFAULT_RESIZE_TIMER;
            }
        }

        // Update the UI scale if needed
        if (app.ui.request_scale_update) {
            app.ui.scale = app.settings.video.autodetect_scale ? app.ui.display_scale : app.settings.video.scale;
            app_sdl_video_update_scale(&app);
            app.ui.request_scale_update = false;
        }

        elapsed_ms = ((float)(sdl_counters[1] - sdl_counters[0]) / (float)SDL_GetPerformanceFrequency()) * 1000.f;

        // Handle the power-save mode.
        //
        // Required because imgui uses quite a lot of CPU even when nothing is happening.
        if (app.emulation.is_started && app.emulation.is_running) {
            // If the emulator is running without vsync, cap the gui's FPS to 4x the display's refresh rate
            if (!app.settings.video.vsync) {
                SDL_Delay(max(0.f, floor((1000.f / (4.0 * app.ui.display_refresh_rate)) - elapsed_ms)));
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

        // Handle all the stuff that must disappear after a few seconds if the mouse isn't moving
        // and the UI isn't being used.
        if (app.emulation.is_started && app.emulation.is_running && !igGetHoveredID() && !igGetFocusID() && !app.ui.settings.open) {

            if (app.ui.menubar.force_show) {
                app.ui.time_elapsed_since_last_mouse_motion_ms = 0.0f;
                app.ui.menubar.visibility = 1.0f;
                app.ui.menubar.force_show = false;
            } else if (app.ui.menubar.force_hide) {
                app.ui.time_elapsed_since_last_mouse_motion_ms = 1950.0f;
                app.ui.menubar.visibility = 1.0f;
                app.ui.menubar.force_hide = false;
            } else if (app.ui.time_elapsed_since_last_mouse_motion_ms <= 2000.0) {
                app.ui.time_elapsed_since_last_mouse_motion_ms += elapsed_ms;
            }

            // Hide the cursor if the mouse is inactive for a while
            if (app.settings.video.hide_cursor_when_mouse_inactive) {
                bool show_cursor;
                bool is_cursor_visible;

                is_cursor_visible = igGetMouseCursor() != ImGuiMouseCursor_None;
                show_cursor = (app.ui.time_elapsed_since_last_mouse_motion_ms < 2000.0);

                if (show_cursor != is_cursor_visible) {
                    igSetMouseCursor(show_cursor ? ImGuiMouseCursor_Arrow : ImGuiMouseCursor_None);
                }
            }

            // Hide the menubar if the mouse is inactive for a while
            // We slowly change `visibility` to go from 1.0 to 0.0 over 50ms, after the mouse is inactive for 1950ms.
            if (app.settings.video.menubar_mode == MENUBAR_MODE_HOVER_OVER_GAME) {
                if (app.ui.time_elapsed_since_last_mouse_motion_ms < 1950.0) {
                    app.ui.menubar.visibility = 1.0f;
                } else if (app.ui.time_elapsed_since_last_mouse_motion_ms >= 1950.0 && app.ui.time_elapsed_since_last_mouse_motion_ms <= 2000.0) {
                    app.ui.menubar.visibility = (2000.0 - app.ui.time_elapsed_since_last_mouse_motion_ms) / 50.0;
                } else {
                    app.ui.menubar.visibility = 0.0f;
                }
            }
        } else {
            app.ui.time_elapsed_since_last_mouse_motion_ms = 0;

            if (igGetMouseCursor() == ImGuiMouseCursor_None) {
                igSetMouseCursor(ImGuiMouseCursor_Arrow);
            }

            app.ui.menubar.visibility = 1.0f;
            app.ui.menubar.force_hide = false;
            app.ui.menubar.force_show = false;
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
