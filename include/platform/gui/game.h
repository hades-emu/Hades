/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#ifndef PLATFORM_GUI_GAME_H
# define PLATFORM_GUI_GAME_H

# define SDL_MAIN_HANDLED
# define CIMGUI_DEFINE_ENUMS_AND_STRUCTS

# include <GL/glew.h>
# include <SDL2/SDL.h>
# include <cimgui.h>
# include "hades.h"
# include "gba/gba.h"

# define MAX_RECENT_ROMS            5

struct gba;
struct ImGuiIO;

struct app {
    bool run;

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
        float sound_level;
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
};

/* platform/gui/game/features/config.c */
void gui_config_load(struct app *app);
void gui_config_save(struct app *app);
void gui_config_push_recent_rom(struct app *app);

/* platform/gui/game/features/screenshot.c */
void gui_screenshot(struct app *app);

/* platform/gui/game/sdl/audio.c */
void gui_sdl_audio_init(struct app *app);
void gui_sdl_audio_cleanup(struct app *app);

/* platform/gui/game/sdl/init.c */
void gui_sdl_init(struct app *app);
void gui_sdl_cleanup(struct app *app);

/* platform/gui/game/sdl/input.c */
void gui_sdl_handle_inputs(struct app *app);

/* platform/gui/game/sdl/video.c */
void gui_sdl_video_init(struct app *app);
void gui_sdl_video_cleanup(struct app *app);
void gui_sdl_video_render_frame(struct app *app);

/* platform/gui/game/windows/error.c */
void gui_new_error(struct app *app, char *msg);
void gui_win_error(struct app *app);

/* platform/gui/game/windows/game.c */
void gui_win_game(struct app *app);

/* platform/gui/game/windows/menubar.c */
void gui_win_menubar(struct app *app);

#endif /* !PLATFORM_GUI_GAME_H */