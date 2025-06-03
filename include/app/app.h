/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
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
#include "gba/gba.h"

#define GLSL(src)                   "#version 330 core\n" #src

#define MAX_RECENT_ROMS             10
#define MAX_QUICKSAVES              10
#define POWER_SAVE_FRAME_DELAY      30
#define MAX_GFX_PROGRAMS            10

#define DEFAULT_RESIZE_TIMER        3

struct ImGuiIO;

enum menubar_mode {
    MENUBAR_MODE_FIXED_ABOVE_GAME = 0,
    MENUBAR_MODE_HOVER_OVER_GAME = 1,

    MENUBAR_MODE_LEN,
    MENUBAR_MODE_MIN = 0,
    MENUBAR_MODE_MAX = 1,
};

enum display_mode {
    DISPLAY_MODE_WINDOWED = 0,
    DISPLAY_MODE_BORDERLESS = 1,
    DISPLAY_MODE_FULLSCREEN = 2,

    DISPLAY_MODE_LEN,
    DISPLAY_MODE_MIN = 0,
    DISPLAY_MODE_MAX = 2,
};

enum texture_filter_kind {
    TEXTURE_FILTER_NEAREST = 0,
    TEXTURE_FILTER_LINEAR = 1,

    TEXTURE_FILTER_LEN,
    TEXTURE_FILTER_MIN = 0,
    TEXTURE_FILTER_MAX = 1,
};

enum pixel_color_filter_kind {
    PIXEL_COLOR_FILTER_NONE = 0,
    PIXEL_COLOR_FILTER_COLOR_CORRECTION = 1,
    PIXEL_COLOR_FILTER_GREY_SCALE = 2,

    PIXEL_COLOR_FILTER_LEN,
    PIXEL_COLOR_FILTER_MIN = 0,
    PIXEL_COLOR_FILTER_MAX = 2,
};

enum pixel_scaling_filter_kind {
    PIXEL_SCALING_FILTER_NONE = 0,
    PIXEL_SCALING_FILTER_LCD_GRID = 1,
    PIXEL_SCALING_FILTER_LCD_GRID_WITH_RGB_STRIPES = 2,

    PIXEL_SCALING_FILTER_LEN,
    PIXEL_SCALING_FILTER_MIN = 0,
    PIXEL_SCALING_FILTER_MAX = 2,
};

enum aspect_ratio {
    ASPECT_RATIO_BORDERS = 0,
    ASPECT_RATIO_STRETCH = 1,

    ASPECT_RATIO_LEN,
    ASPECT_RATIO_MIN = 0,
    ASPECT_RATIO_MAX = 1,
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

    BIND_EMULATOR_RESET,
    BIND_EMULATOR_MUTE,
    BIND_EMULATOR_PAUSE,
    BIND_EMULATOR_STOP,
    BIND_EMULATOR_SHOW_FPS,
    BIND_EMULATOR_FULLSCREEN,
    BIND_EMULATOR_SCREENSHOT,
    BIND_EMULATOR_SETTINGS,
    BIND_EMULATOR_ALT_SPEED_HOLD,
    BIND_EMULATOR_ALT_SPEED_TOGGLE,
    BIND_EMULATOR_QUICKSAVE_1,
    BIND_EMULATOR_QUICKSAVE_2,
    BIND_EMULATOR_QUICKSAVE_3,
    BIND_EMULATOR_QUICKSAVE_4,
    BIND_EMULATOR_QUICKSAVE_5,
    BIND_EMULATOR_QUICKSAVE_6,
    BIND_EMULATOR_QUICKSAVE_7,
    BIND_EMULATOR_QUICKSAVE_8,
    BIND_EMULATOR_QUICKSAVE_9,
    BIND_EMULATOR_QUICKSAVE_10,
    BIND_EMULATOR_QUICKLOAD_1,
    BIND_EMULATOR_QUICKLOAD_2,
    BIND_EMULATOR_QUICKLOAD_3,
    BIND_EMULATOR_QUICKLOAD_4,
    BIND_EMULATOR_QUICKLOAD_5,
    BIND_EMULATOR_QUICKLOAD_6,
    BIND_EMULATOR_QUICKLOAD_7,
    BIND_EMULATOR_QUICKLOAD_8,
    BIND_EMULATOR_QUICKLOAD_9,
    BIND_EMULATOR_QUICKLOAD_10,

    BIND_MAX,
    BIND_MIN = BIND_GBA_A,

    BIND_GBA_MIN = BIND_GBA_A,
    BIND_GBA_MAX = BIND_GBA_SELECT,
    BIND_EMULATOR_MIN = BIND_EMULATOR_RESET,
    BIND_EMULATOR_MAX = BIND_EMULATOR_QUICKLOAD_10,
};

extern char const * const binds_pretty_name[];
extern char const * const binds_slug[];

enum app_notification_kind {
    UI_NOTIFICATION_INFO,
    UI_NOTIFICATION_SUCCESS,
    UI_NOTIFICATION_ERROR,
};

enum menu_kind {
    MENU_GENERAL,
    MENU_EMULATION,
    MENU_VIDEO,
    MENU_AUDIO,
    MENU_BINDINGS,

    MENU_MAX,
};

struct app_notification {
    enum app_notification_kind kind;
    char *msg;
    uint64_t timeout;
    uint64_t fade_time_start;
    struct app_notification *next;
};

struct keyboard_binding {
    SDL_Keycode key;

    // Modifiers
    bool ctrl;
    bool alt;
    bool shift;
};

struct settings {
    struct {
        // Show FPS
        bool show_fps;

        // Start the last played game on startup, when no game is provided
        bool start_last_played_game_on_startup;

        // Pause when the window is inactive
        bool pause_when_window_inactive;

        // Pause when the game resets
        bool pause_when_game_resets;
    } general;
    struct {
        // BIOS Path
        char *bios_path;

        // Skip BIOS intro
        bool skip_bios_intro;

        // Speed
        //   <= 0: Unlimited
        //   1.0: 60fps
        //   2.0: 120fps
        //   etc.
        float speed;

        // Alternative speed
        //   <= 0: Unlimited
        //   1.0: 60fps
        //   2.0: 120fps
        //   etc.
        float alt_speed;

        // Backup storage
        struct {
            bool autodetect;
            enum backup_storage_types type;
        } backup_storage;

        // GPIO
        struct {
            bool autodetect;
            enum gpio_device_types type;
        } gpio_device;

        // Enable the emulation of the prefetch buffer
        bool prefetch_buffer;
    } emulation;

    struct {
        // Menubar mode (fixed above game or hover over game)
        enum menubar_mode menubar_mode;

        // Display mode
        enum display_mode display_mode;

        // Auto-detect the scale
        bool autodetect_scale;

        // Scale to use for the UI if `autodetect_scale` is false.
        // Must be > 0.0
        float scale;

        // Display size
        uint32_t display_size;

        // Aspect Ratio (Black borders, Stretch, etc.)
        enum aspect_ratio aspect_ratio;

        // VSync
        bool vsync;

        // Texture Filter (Linear, Nearest)
        enum texture_filter_kind texture_filter;

        // Color Filter (Color Correction)
        enum pixel_color_filter_kind pixel_color_filter;

        // Pixel Scaling Filter (LCD Grid, xBRZ, etc.)
        enum pixel_scaling_filter_kind pixel_scaling_filter;

        // Hide the cursor after a few seconds of inactivity
        bool hide_cursor_when_mouse_inactive;

        // If set, use the system screenshot directory.
        // Otherwise, use the one specified by `screenshot_dir`.
        // TODO: Move this elsewhere
        bool use_system_screenshot_dir_path;

        // Screenshot directory
        // Only relevant if `use_system_screenshot_dir` is set.
        // TODO: Move this elsewhere
        char *screenshot_dir_path;

        /*
        ** Debug
        */

        // Enable BG Layer X
        bool enable_bg_layers[4];

        // Enable OAM (Sprites)
        bool enable_oam;
    } video;

    struct {
        // Mute all the emulator's sounds
        bool mute;

        // Level of the sound (0.0 to 1.0)
        float level;

        /*
        ** Debug
        */

        // Enable PSG Channel X
        bool enable_psg_channels[4];

        // Enable FIFO Channel
        bool enable_fifo_channels[2];
    } audio;
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
        float fps;

        // Set to true when the alternative speed should be used
        bool use_alt_speed;

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

        // Game controller
        struct {
            SDL_GameController *ptr;
            bool connected;
            struct {
                SDL_JoystickID idx;
                SDL_Joystick *ptr;
                bool can_rumble;
                bool up;
                bool down;
                bool right;
                bool left;
            } joystick;
        } controller;
    } sdl;

    struct {
        SDL_GLContext gl_context;

        GLuint game_texture;
        GLuint pixel_color_texture;
        GLuint pixel_scaling_texture;
        GLuint fbo;
        GLuint vao;
        GLuint vbo;

        GLuint program_color_correction;
        GLuint program_grey_scale;
        GLuint program_lcd_grid;
        GLuint program_lcd_grid_with_rgb_stripes;

        GLuint pixel_color_program;

        GLuint pixel_scaling_program;
        size_t pixel_scaling_size;
    } gfx;

    struct {
        char *sys_pictures_dir_path;
        char *sys_config_path;

        char *recent_roms[MAX_RECENT_ROMS];

        struct {
            char *path;
            char *mtime;
            bool exist;
        } qsaves[MAX_QUICKSAVES];

        // Set to true if both the `mtime` and `exist` field of `qsaves` needs to be refreshed.
        bool flush_qsaves_cache;
    } file;

    struct {
        uint32_t resample_frequency;
    } audio;

    struct {
        // ImGui internal stuff
        struct ImGuiIO *ioptr;

        struct {
            struct ImFont *normal;
            struct ImFont *big;
        } fonts;

        // Display's metadata
        float display_dpi;
        float display_scale;
        uint32_t display_refresh_rate;

        // UI Scale
        // Usually the display scale unless overridden in the settings
        float scale;

        // Set to update the UI scale to match `app.video.scale` at the
        // end of the frame.
        bool request_scale_update;

        // Default style of ImGui.
        // Used when rescaling the application.
        struct ImGuiStyle default_style;

        // How many frames before going back to power save mode?
        uint32_t power_save_fcounter;

        // Temporary value used to measure the FPS.
        uint32_t ticks_last_frame;

        // Temporary value used to measure the time since the last mouse movement (in ms)
        float time_elapsed_since_last_mouse_motion_ms;

        struct {
            // Force the menubar to be hidden on the next frame
            bool force_hide;

            // Force the menubar to be visible on the next frame
            bool force_show;

            // 1.0 if the menubar is visible, 0.0 if not, and something in between if the
            // menubar is fading away
            float visibility;

            // Width of the FPS counter within the menubar.
            float fps_width;

            // Size of the menu bar
            ImVec2 size;
        } menubar;

        struct {
            // The game area is made of two sub areas: the inner game area and the outer game area.
            //
            // The outer game area is a subset of the window area that represents where the game should be drawn.
            // It's basically the same as the window area but doesn't include any visible UI elements (such as the menubar).
            // The inner game area is a subset of the outer game area and trully represent the area where the game is drawn.
            //
            // The difference between the two is that the outer game area matches the aspect ratio of the window, which might not
            // be the same than the one of the GBA. If they mismatch and the aspect ratio is set to "black borders", then the
            // inner game area will be the subset where the game is drawn, without the black borders, while the outer game area
            // will also include the black borders around the game.
            //
            // In other words, the inner game area is contained within the outer one, and can only be smaller or equal.
            struct {
                struct {
                    uint32_t x;
                    uint32_t y;
                    uint32_t width;
                    uint32_t height;
                } inner;

                struct {
                    uint32_t x;
                    uint32_t y;
                    uint32_t width;
                    uint32_t height;
                } outer;
            } game;

            // The size of the window area.
            // Exactly equal to the size of the window
            struct {
                uint32_t width;
                uint32_t height;
            } win;

            // Timer, in frames, until the window needs to be resized to fit a specific aspect ratio
            int resize_request_timer;

            // Set to the last time the scale was calculated.
            uint64_t last_scale_calculation_ms;
        } display;

        // The error message to print, if any.
        struct {
            char *msg;
            bool active;
        } error;

        struct {
            bool open;

            uint32_t menu;

            struct {
                struct keyboard_binding *keyboard_target;
                SDL_GameControllerButton *controller_target;
            } keybindings_editor;
        } settings;

        struct app_notification *notifications;
    } ui;

    struct {
        struct keyboard_binding keyboard[BIND_MAX];
        struct keyboard_binding keyboard_alt[BIND_MAX];
        SDL_GameControllerButton controller[BIND_MAX];
        SDL_GameControllerButton controller_alt[BIND_MAX];
    } binds;

    struct settings settings;

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
void app_sdl_set_rumble(struct app *app, bool enable);

/* app/sdl/init.c */
void app_sdl_init(struct app *app);
void app_sdl_cleanup(struct app *app);

/* app/sdl/video.c */
void app_sdl_video_init(struct app *app);
void app_sdl_video_cleanup(struct app *app);
void app_sdl_video_render_frame(struct app *app);
void app_sdl_video_rebuild_pipeline(struct app *app);
void app_sdl_video_resize_window(struct app *app);
void app_sdl_video_update_display_mode(struct app *app);
void app_sdl_video_update_scale(struct app *app);
float app_sdl_video_calculate_scale(struct app *app);

/* app/shaders/frag-color-correction.c */
extern char const *SHADER_FRAG_COLOR_CORRECTION;

/* app/shaders/frag-gameboy.c */
extern char const *SHADER_FRAG_GAMEBOY;

/* app/shaders/frag-grey-scale.c */
extern char const *SHADER_FRAG_GREY_SCALE;

/* app/shaders/frag-lcd-grid-with-rgb-stripes.c */
extern char const *SHADER_FRAG_LCD_GRID_WITH_RGB_STRIPES;

/* app/shaders/frag-lcd-grid.c */
extern char const *SHADER_FRAG_LCD_GRID;

/* app/shaders/vertex-common.c */
extern char const *SHADER_VERTEX_COMMON;

/* app/windows/game.c */
void app_win_game(struct app *app);
void app_win_game_refresh_game_area(struct app *app);

/* app/windows/menubar.c */
void app_win_menubar(struct app *app);

/* app/windows/notif.c */
void app_new_notification(struct app *app, enum app_notification_kind, char const *msg, ...);
void app_win_notifications(struct app *app);

/* app/windows/settings.c */
void app_win_settings(struct app *app);

/* args.c */
void app_args_parse(struct app *app, int argc, char * const argv[]);

/* bindings.c */
void app_bindings_setup_default(struct app *app);
void app_bindings_keyboard_binding_build(struct keyboard_binding *, SDL_Keycode key, bool ctrl, bool alt, bool shift);
void app_bindings_keyboard_binding_clear(struct app *app, struct keyboard_binding const *binding);
bool app_bindings_keyboard_binding_match(struct keyboard_binding const *, struct keyboard_binding const *);
char *app_bindings_keyboard_binding_to_str(struct keyboard_binding const *bind);
void app_bindings_controller_binding_clear(struct app *app, SDL_GameControllerButton btn);
void app_bindings_process(struct app *app, enum bind_actions bind, bool pressed);

/* config.c */
void app_config_load(struct app *app);
void app_config_save(struct app *app);
void app_config_push_recent_rom(struct app *app, char const *path);

/* emulator.c */
void app_emulator_process_all_notifs(struct app *app);
bool app_emulator_configure_and_run(struct app *app, char const *rom_path, char const *backup_to_import);
void app_emulator_reset(struct app *app);
void app_emulator_stop(struct app *app);
void app_emulator_run(struct app *app);
void app_emulator_pause(struct app *app);
void app_emulator_exit(struct app *app);
void app_emulator_key(struct app *app, enum keys key, bool pressed);
void app_emulator_settings(struct app *app);
void app_emulator_export_save_to_path(struct app *app, char const *);
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

/* path.c */
void app_paths_update(struct app *app);
char const *app_path_config(struct app *app);
char const *app_path_screenshots(struct app *app);
