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
# define MAX_QUICKSAVES             5
# define POWER_SAVE_FRAME_DELAY     30

enum texture_filter_kind {
    TEXTURE_FILTER_NEAREST = 0,
    TEXTURE_FILTER_LINEAR,
};

struct ImGuiIO;

enum bind_actions {
    BIND_UNASSIGNED = 0,

    BIND_GBA_A,
    BIND_GBA_B,
    BIND_GBA_L,
    BIND_GBA_R,
    BIND_GBA_UP,
    BIND_GBA_DOWN,
    BIND_GBA_LEFT,
    BIND_GBA_RIGHT,
    BIND_GBA_START,
    BIND_GBA_SELECT,

    BIND_EMULATOR_UNBOUNDED_SPEED,
    BIND_EMULATOR_SCREENSHOT,
    BIND_EMULATOR_QUICKSAVE,
    BIND_EMULATOR_QUICKLOAD,

    BIND_MAX,
    BIND_MIN = BIND_GBA_A,
};

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

        // Skip BIOS
        bool skip_bios;

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

        struct {
            char *path;
            char *mtime;
            bool exist;
        } qsaves[MAX_QUICKSAVES];

        bool flush_qsaves_cache;
    } file;

    struct {
        bool vsync;
        bool color_correction;
        uint32_t display_size;

        struct {
            enum texture_filter_kind kind;
            bool refresh;
        } texture_filter;

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

        /* Display refresh rate */
        uint32_t refresh_rate;

        /* How many frames before going back to power save mode? */
        uint32_t power_save_fcounter;

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

    struct {
        /*
        ** For the keyboard, we bind a key to each action.
        ** For controllers, we bind an action to each key.
        */

        SDL_Keycode keyboard[BIND_MAX];
        enum bind_actions controller[SDL_CONTROLLER_BUTTON_MAX];
    } binds;

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

/* common/game.c */
void app_game_reset(struct app *app);
void app_game_stop(struct app *app);
void app_game_run(struct app *app);
void app_game_pause(struct app *app);
void app_game_write_backup(struct app *app);
void app_game_screenshot(struct app *app);
void app_game_quicksave(struct app *, size_t);
void app_game_quickload(struct app *, size_t);

#ifdef WITH_DEBUGGER
void app_game_frame(struct app *app);
void app_game_trace(struct app *app, size_t, void (*)(struct app *));
void app_game_step(struct app *app, bool over, size_t cnt);
#endif

#endif /* !GUI_APP_H */
