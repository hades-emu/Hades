/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#ifndef GUI_APP_H
# define GUI_APP_H

# define SDL_MAIN_HANDLED
# define CIMGUI_DEFINE_ENUMS_AND_STRUCTS

# if WITH_DEBUGGER
#  include <capstone/capstone.h>
# endif

# include <stdatomic.h>
# include <GL/glew.h>
# include <SDL2/SDL.h>
# include <cimgui.h>
# include "hades.h"
# include "gba/gba.h"

# define MAX_RECENT_ROMS            5

struct gba;
struct ImGuiIO;

struct app {
    atomic_bool run;

    struct {
        struct gba *gba;

        bool started;
        bool running;

        // Current FPS
        uint32_t fps;

        // Speed
        uint32_t speed;
        bool unbounded;

        // Backup storage
        enum backup_storage_types backup_type;

        // RTC
        bool rtc_autodetect;
        bool rtc_force_enabled;
    } emulation;

    struct {
        SDL_Window *window;
        SDL_GLContext gl_context;
        SDL_AudioDeviceID audio_device;
        GLuint game_texture;

        /* Game controller */
        struct {
            SDL_GameController *ptr;
            bool connected;
            struct {
                SDL_JoystickID idx;
                bool up;
                bool down;
                bool right;
                bool left;
            } joystick;
        } controller;
    } sdl;

    struct {
        char *config_path;

        char *bios_path;
        char *game_path;
        char *recent_roms[MAX_RECENT_ROMS];

        char *backup_path;
        FILE *backup_file;
        char *qsave_path;
    } file;

    struct {
        bool vsync;
        bool color_correction;
        uint32_t display_size;
    } video;

    struct {
        bool mute;
        float level;
    } audio;

    struct {
        /* ImGui internal stuff */
        struct ImGuiIO *ioptr;

        /* High resolution */
        float dpi;
        uint32_t scale;

        /* Size of the menu bar, used to re-scale the window */
        ImVec2 menubar_size;

        /* Size of the FPS counter within the menubar. */
        float menubar_fps_width;

        // Temporary value used to measure the FPS.
        uint32_t ticks_last_frame;

        /* The error message to print, if any. */
        struct {
            char *msg;
            bool active;
        } error;

        /* Indicates if the user wants to resize the windows to `video->display_size`. */
        bool refresh_windows_size;
    } ui;

#if WITH_DEBUGGER
    struct {
        csh handle_arm;             // Capstone handle for ARM mode
        csh handle_thumb;           // Capstone handle for Thumb mode

        struct variable *variables;
        size_t variables_len;

        struct breakpoint *breakpoints;
        size_t breakpoints_len;

        struct watchpoint *watchpoints;
        size_t watchpoints_len;
    } debugger;
#endif
};

/* platform/gui/features/config.c */
void gui_config_load(struct app *app);
void gui_config_save(struct app *app);
void gui_config_push_recent_rom(struct app *app);

/* platform/gui/features/screenshot.c */
void gui_screenshot(struct app *app);

/* platform/gui/sdl/audio.c */
void gui_sdl_audio_init(struct app *app);
void gui_sdl_audio_cleanup(struct app *app);

/* platform/gui/sdl/init.c */
void gui_sdl_init(struct app *app);
void gui_sdl_cleanup(struct app *app);

/* platform/gui/sdl/input.c */
void gui_sdl_handle_inputs(struct app *app);

/* platform/gui/sdl/video.c */
void gui_sdl_video_init(struct app *app);
void gui_sdl_video_cleanup(struct app *app);
void gui_sdl_video_render_frame(struct app *app);

/* platform/gui/windows/error.c */
void gui_new_error(struct app *app, char *msg);
void gui_win_error(struct app *app);

/* platform/gui/windows.c */
void gui_win_game(struct app *app);

/* platform/gui/windows/menubar.c */
void gui_win_menubar(struct app *app);

/* platform/gui/game.c */
void gui_game_reset(struct app *app);
void gui_game_stop(struct app *app);
void gui_game_run(struct app *app);
void gui_game_pause(struct app *app);
void gui_game_trace(struct app *app, size_t, void (*)(struct app *));
void gui_game_step(struct app *app, bool over, size_t cnt);
void gui_game_write_backup(struct app *app);

#endif /* !GUI_APP_H */