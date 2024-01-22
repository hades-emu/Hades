/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#pragma once

#if WITH_DEBUGGER
#include <capstone/capstone.h>
#endif

#include <stdatomic.h>
#include <GL/glew.h>
#include <SDL2/SDL.h>
#include <cimgui.h>
#include "hades.h"
#include "gba/gba.h"

#define GLSL(src)                   "#version 330 core\n" #src

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

    BIND_EMULATOR_SPEED_MAX,
    BIND_EMULATOR_SPEED_X1,
    BIND_EMULATOR_SPEED_X2,
    BIND_EMULATOR_SPEED_X3,
    BIND_EMULATOR_SPEED_X4,
    BIND_EMULATOR_SPEED_X5,
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
    BIND_EMULATOR_MIN = BIND_EMULATOR_SPEED_MAX,
    BIND_EMULATOR_MAX = BIND_EMULATOR_RESET,
};

extern char const * const binds_pretty_name[];
extern char const * const binds_slug[];

enum ui_notification_kind {
    UI_NOTIFICATION_INFO,
    UI_NOTIFICATION_SUCCESS,
    UI_NOTIFICATION_ERROR,
};

struct ui_notification {
    enum ui_notification_kind kind;
    char *msg;
    uint64_t timeout;
    uint64_t fade_time_start;
    struct ui_notification *next;
};

struct app {
    atomic_bool run;

    struct args {
        char const *rom_path;
        char const *bios_path;
        char const *config_path;
        bool with_gui;
    } args;

    struct {
        struct gba *gba;
        struct launch_config *launch_config;
        struct game_entry *game_entry;

        char *game_path;

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
        GLuint game_texture_a;
        GLuint game_texture_b;
        GLuint fbo;
        GLuint vao;
        GLuint vbo;

        GLuint program_color_correction;
        GLuint program_lcd_grid;

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
        bool lcd_grid;
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

        struct ui_notification *notifications;
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

/* app/sdl/audio.c */
void app_sdl_audio_init(struct app *app);
void app_sdl_audio_cleanup(struct app *app);

/* app/sdl/event.c */
void app_sdl_handle_events(struct app *app);

/* app/sdl/init.c */
void app_sdl_init(struct app *app);
void app_sdl_cleanup(struct app *app);

/* app/sdl/video.c */
void app_sdl_video_init(struct app *app);
void app_sdl_video_cleanup(struct app *app);
void app_sdl_video_render_frame(struct app *app);
void app_sdl_video_rebuild_pipeline(struct app *app);

/* app/shaders/frag-color-correction.c */
extern char const *SHADER_FRAG_COLOR_CORRECTION;

/* app/shaders/frag-lcd-grid.c */
extern char const *SHADER_FRAG_LCD_GRID;

/* app/shaders/vertex-common.c */
extern char const *SHADER_VERTEX_COMMON;

/* app/windows/game.c */
void app_win_game(struct app *app);

/* app/windows/keybinds.c */
void app_win_keybinds_editor(struct app *app);

/* app/windows/menubar.c */
void app_win_menubar(struct app *app);

/* app/windows/notif.c */
void app_new_notification(struct app *app, enum ui_notification_kind, char const *msg, ...);
void app_win_notifications(struct app *app);

/* args.c */
void app_args_parse(struct app *app, int argc, char * const argv[]);

/* bindings.c */
void app_bindings_setup_default(struct app *app);
void app_bindings_keyboard_clear(struct app *app, SDL_Keycode key);
void app_bindings_controller_clear(struct app *app, SDL_GameControllerButton btn);
void app_bindings_handle(struct app *app, enum bind_actions bind, bool pressed);

/* config.c */
void app_config_load(struct app *app);
void app_config_save(struct app *app);
void app_config_push_recent_rom(struct app *app, char const *path);

/* emulator.c */
void app_emulator_process_all_notifs(struct app *app);
bool app_emulator_configure(struct app *app, char const *rom_path);
void app_emulator_reset(struct app *app);
void app_emulator_stop(struct app *app);
void app_emulator_run(struct app *app);
void app_emulator_pause(struct app *app);
void app_emulator_exit(struct app *app);
void app_emulator_key(struct app *app, enum keys key, bool pressed);
void app_emulator_speed(struct app *app, uint32_t);
void app_emulator_update_backup(struct app *app);
void app_emulator_screenshot(struct app *app);
void app_emulator_screenshot_path(struct app *app, char const *);
void app_emulator_quicksave(struct app *app, size_t idx);
void app_emulator_quickload(struct app *app, size_t idx);

#ifdef WITH_DEBUGGER

void app_emulator_frame(struct app *app, size_t);
void app_emulator_trace(struct app *app, size_t, void (*)(struct app *));
void app_emulator_step_in(struct app *app, size_t cnt);
void app_emulator_step_over(struct app *app, size_t cnt);
void app_emulator_set_breakpoints_list(struct app *app, struct breakpoint *breakpoints, size_t len);
void app_emulator_set_watchpoints_list(struct app *app, struct watchpoint *watchpoints, size_t len);

#endif
