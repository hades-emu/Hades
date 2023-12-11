/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#pragma once

#define SDL_MAIN_HANDLED
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS

#if WITH_DEBUGGER
#include <capstone/capstone.h>
#endif

#include <stdatomic.h>
#include <GL/glew.h>
#include <SDL2/SDL.h>
#include <cimgui.h>
#include "hades.h"
#include "gba/gba.h"

#define MAX_RECENT_ROMS             5
#define MAX_QUICKSAVES              5
#define POWER_SAVE_FRAME_DELAY      30
#define MAX_GFX_PROGRAMS            10

struct ImGuiIO;

enum texture_filter_kind {
    TEXTURE_FILTER_MIN = 0,

    TEXTURE_FILTER_NEAREST = 0,
    TEXTURE_FILTER_LINEAR = 1,

    TEXTURE_FILTER_MAX = 1,
};

enum aspect_ratio {
    ASPECT_RATIO_MIN = 0,

    ASPECT_RATIO_RESIZE = 0,
    ASPECT_RATIO_BORDERS = 1,
    ASPECT_RATIO_STRETCH = 2,

    ASPECT_RATIO_MAX = 2,
};

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

    BIND_EMULATOR_SPEED_X1,
    BIND_EMULATOR_SPEED_X2,
    BIND_EMULATOR_SPEED_X3,
    BIND_EMULATOR_SPEED_X4,
    BIND_EMULATOR_SPEED_X5,
    BIND_EMULATOR_SPEED_MAX_TOGGLE,
    BIND_EMULATOR_SPEED_MAX_HOLD,
    BIND_EMULATOR_SCREENSHOT,
    BIND_EMULATOR_QUICKSAVE,
    BIND_EMULATOR_QUICKLOAD,
    BIND_EMULATOR_PAUSE,
    BIND_EMULATOR_RESET,

    BIND_MAX,
    BIND_MIN = BIND_GBA_A,

    BIND_GBA_MIN = BIND_GBA_A,
    BIND_GBA_MAX = BIND_GBA_SELECT,
    BIND_EMULATOR_MIN = BIND_EMULATOR_SPEED_X1,
    BIND_EMULATOR_MAX = BIND_EMULATOR_RESET,
};

extern char const * const binds_pretty_name[];
extern char const * const binds_slug[];

struct app {
    atomic_bool run;

    struct args {
        char const *rom_path;
        char const *bios_path;
    } args;

    struct {
        struct gba *gba;
        struct launch_config *launch_config;
        struct game_entry *game_entry;

        FILE *backup_file;

        bool is_started;
        bool is_running;

        // Current FPS
        uint32_t fps;

        // Speed
        uint32_t speed;
        bool unbounded;

        // Skip BIOS
        bool skip_bios;

        // Backup storage
        struct {
            bool autodetect;
            enum backup_storage_types type;
        } backup_storage;

        // RTC
        struct {
            bool autodetect;
            bool enabled;
        } rtc;

        // The current quicksave request
        struct {
            bool enabled;
            size_t idx;
        } quicksave_request;

        // The current quickload request
        struct {
            bool enabled;
            void *data;
        } quickload_request;
    } emulation;

    struct {
        SDL_Window *window;
        SDL_AudioDeviceID audio_device;

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
        SDL_GLContext gl_context;

        enum texture_filter_kind texture_filter;
        GLuint game_texture_in;
        GLuint game_texture_out;
        GLuint fbo;
        GLuint vao;
        GLuint vbo;

        GLuint program_color_correction;

        GLuint active_programs[MAX_GFX_PROGRAMS];
        size_t active_programs_length;
    } gfx;

    struct {
        char *config_path;

        char *bios_path;
        char *recent_roms[MAX_RECENT_ROMS];

        struct {
            char *path;
            char *mtime;
            bool exist;
        } qsaves[MAX_QUICKSAVES];

        bool flush_qsaves_cache; // Set to true if the `mtime` and `exist` field of `qsaves` needs to be refreshed.
    } file;

    struct {
        uint32_t display_size;
        enum aspect_ratio aspect_ratio;
        bool vsync;
        bool color_correction;
    } video;

    struct {
        bool mute;
        float level;
        uint32_t resample_frequency;
    } audio;

    struct {
        /* ImGui internal stuff */
        struct ImGuiIO *ioptr;

        struct {
            struct ImFont *normal;
            struct ImFont *big;
        } fonts;

        /* High resolution */
        float dpi;
        uint32_t scale;

        /* Display refresh rate */
        uint32_t refresh_rate;

        /* How many frames before going back to power save mode? */
        uint32_t power_save_fcounter;

        /* Temporary value used to measure the FPS. */
        uint32_t ticks_last_frame;

        /*
        ** The size of the `game` window.
        ** Usually the size of the window minus the menubar's height (if it is visible).
        */
        struct {
            int width;
            int height;
        } game;

        /* Size of the FPS counter within the menubar. */
        float menubar_fps_width;

        /* Size of the menu bar */
        ImVec2 menubar_size;

        struct {
            int width;
            int height;
            bool maximized;

            /* Used when resizing, to know if the new window is bigger or smaller than the previous one. */
            uint32_t old_area;

            /* Indicates if the window needs to be resized */
            bool resize;

            /*
            ** Indicates if the user wants to resize the windows to the given ratio.
            ** Otherwise, `video->display_size` is taken
            **/
            bool resize_with_ratio;
            float resize_ratio;
        } win;

        /* The error message to print, if any. */
        struct {
            char *msg;
            bool active;
        } error;

        struct {
            bool open;
            bool visible;

            SDL_Keycode *keyboard_target;
            SDL_GameControllerButton *controller_target;
        } keybindings_editor;
    } ui;

    struct {
        SDL_Keycode keyboard[BIND_MAX];
        SDL_Keycode keyboard_alt[BIND_MAX];
        SDL_GameControllerButton controller[BIND_MAX];
        SDL_GameControllerButton controller_alt[BIND_MAX];
    } binds;

#if WITH_DEBUGGER
    struct {
        bool is_running;
        bool is_started;

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
void app_game_process_all_notifs(struct app *app);
bool app_game_configure(struct app *app, char const *rom_path);
void app_game_stop(struct app *app);
void app_game_run(struct app *app);
void app_game_pause(struct app *app);
void app_game_reset(struct app *app);
void app_game_exit(struct app *app);
void app_game_key(struct app *app, enum keys key, bool pressed);
void app_game_speed(struct app *app, uint32_t);
void app_game_update_backup(struct app *app);
void app_game_screenshot(struct app *app);
void app_game_quicksave(struct app *app, size_t idx);
void app_game_quickload(struct app *app, size_t idx);

#ifdef WITH_DEBUGGER

void app_game_frame(struct app *app);
void app_game_trace(struct app *app, size_t, void (*)(struct app *));
void app_game_step_in(struct app *app, size_t cnt);
void app_game_step_over(struct app *app, size_t cnt);
void app_game_set_breakpoints_list(struct app *app, struct breakpoint *breakpoints, size_t len);
void app_game_set_watchpoints_list(struct app *app, struct watchpoint *watchpoints, size_t len);

#endif
