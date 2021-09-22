/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef PLATFORM_GUI_H
# define PLATFORM_GUI_H

# include <stdio.h>
# define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
# include <GL/glew.h>
# include <SDL2/SDL.h>
# include <cimgui.h>
# include <ImGuiFileDialog.h>

struct gba;

struct debugger {
    bool enabled;
};

struct emulation {
    struct gba *gba;
    char *game_path;
    char *qsave_path;
    char *backup_path;
    FILE *backup_file;
    char const *bios_path;

    uint32_t fps;

    bool pause;
    bool enabled;
    uint32_t speed;
    bool unbounded;
};

struct app {
    bool run;

    SDL_Window *window;
    SDL_GLContext gl_context;
    ImGuiIO* ioptr;
    ImVec4 bg_color;

    ImGuiFileDialog *fs_dialog;

    struct debugger debugger;
    struct emulation emulation;

    GLuint game_texture;
    uint32_t menubar_height;
    float menubar_fps_width;

    /* High resolution */
    float dpi;
    uint32_t gui_scale;

    /* Game Controller */
    SDL_GameController *controller;
    SDL_JoystickID joystick_idx;
    bool controller_connected;

    /* Recently opened ROMs */
    char *recent_roms[5];

    /* Error handling */
    char *error;
};

/* game/game.c */
void gui_game_handle_events(struct app *app, SDL_Event *event);
void gui_game_reload(struct app *app);
void gui_game_pause(struct app *app);
void gui_game_run(struct app *app);
void gui_game_quicksave(struct app *app);
void gui_game_quickload(struct app *app);

/* game/render.c */
void gui_render_game_fullscreen(struct app *app);

/* game/screenshot.c */
void gui_game_screenshot(struct app *app);

/* config.c */
void gui_push_recent_roms(struct app *app);
void gui_load_config(struct app *app);
void gui_save_config(struct app *app);

/* error.c */
void gui_new_error(struct app *app, char *error);
void gui_render_errors(struct app *app);

/* menubar.c */
void gui_render_menubar(struct app *app);

#endif /* !PLATFORM_GUI_H */