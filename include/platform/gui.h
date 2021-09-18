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
# include <SDL2/SDL.h>
# include <GL/gl.h>
# include <cimgui.h>

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

    bool pause;
    bool enabled;
    uint32_t speed;
};

struct app {
    bool run;

    SDL_Window *window;
    SDL_GLContext gl_context;
    ImGuiIO* ioptr;
    ImVec4 bg_color;

    struct debugger debugger;
    struct emulation emulation;

    GLuint game_texture;
    uint32_t menubar_height;

    /* High resolution */
    float dpi;
    uint32_t gui_scale;

    /* Game Controller */
    SDL_GameController *controller;
    SDL_JoystickID joystick_idx;
    bool controller_connected;

    /* Error handling */
    char *error;
};

/* error.c */
void gui_new_error(struct app *app, char *error);
void gui_errors(struct app *app);

/* game.c */
void gui_game_fullscreen(struct app *app);
void gui_game_handle_events(struct app *app, SDL_Event *event);
void gui_reload_game(struct app *app);

/* menubar.c */
void gui_main_menu_bar(struct app *app);

#endif /* !PLATFORM_GUI_H */