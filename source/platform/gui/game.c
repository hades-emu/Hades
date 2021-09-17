/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <errno.h>
#include <stdio.h>
#include <cimgui.h>
#include <GL/gl.h>
#include "hades.h"
#include "platform/gui.h"
#include "gba/gba.h"

static
bool
gui_load_bios(
    struct app *app
) {
    FILE *file;
    void *data;
    char *error_msg;

    file = fopen(app->emulation.bios_path, "rb");
    if (!file) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "failed to open %s: %s.\n",
            app->emulation.bios_path,
            strerror(errno)
        ));
        gui_new_error(app, error_msg);
        return (true);
    }

    fseek(file, 0, SEEK_END);
    if (ftell(file) != 0x4000) {
        error_msg = strdup("the BIOS is invalid.");
        gui_new_error(app, error_msg);
        return (true);
    }

    rewind(file);

    data = calloc(1, BIOS_SIZE);
    hs_assert(data);

    if (fread(data, 1, BIOS_SIZE, file) != BIOS_SIZE) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "failed to read %s: %s.\n",
            app->emulation.bios_path,
            strerror(errno)
        ));
        gui_new_error(app, error_msg);
        free(data);
        return (true);
    }

    gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_LOAD_BIOS(data, free));

    return (false);
}

static
bool
gui_load_rom(
    struct app *app
) {
    FILE *file;
    size_t file_len;
    void *data;
    char *error_msg;

    file = fopen(app->emulation.game_path, "rb");
    if (!file) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "failed to open %s: %s.\n",
            app->emulation.game_path,
            strerror(errno)
        ));
        gui_new_error(app, error_msg);
        return (true);
    }

    fseek(file, 0, SEEK_END);
    file_len = ftell(file);
    if (file_len > CART_SIZE || file_len < 192) {
        error_msg = strdup("the ROM is invalid.");
        gui_new_error(app, error_msg);
        return (true);
    }

    rewind(file);

    data = calloc(1, CART_SIZE);
    hs_assert(data);

    if (fread(data, 1, CART_SIZE, file) != file_len) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "failed to read %s: %s.\n",
            app->emulation.game_path,
            strerror(errno)
        ));
        gui_new_error(app, error_msg);
        free(data);
        return (true);
    }

    gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_LOAD_ROM(data, free));
    gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_BACKUP_TYPE(BACKUP_AUTODETECT));

    return (false);
}

static
bool
gui_load_save(
    struct app *app
) {
    size_t file_len;
    char *error_msg;

    if (app->emulation.backup_file) {
        fclose(app->emulation.backup_file);
    }

    app->emulation.backup_file = fopen(app->emulation.backup_path, "rb+");
    if (app->emulation.backup_file) {
        void *data;
        size_t read_len;

        fseek(app->emulation.backup_file, 0, SEEK_END);
        file_len = ftell(app->emulation.backup_file);
        rewind(app->emulation.backup_file);

        data = calloc(1, file_len);
        hs_assert(data);
        read_len = fread(data, 1, file_len, app->emulation.backup_file);

        if (read_len != file_len) {
            logln(HS_WARNING, "Failed to read the save file. Is it corrupted?");
        } else {
            logln(HS_GLOBAL, "Save data successfully loaded.");
            gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_LOAD_BACKUP(data, file_len, free));
        }

    } else {
        logln(HS_WARNING, "Failed to open the save file. A new one is created instead.");

        app->emulation.backup_file = fopen(app->emulation.backup_path, "wb+");

        if (!app->emulation.backup_file) {
            hs_assert(-1 != asprintf(
                &error_msg,
                "failed to create %s: %s.\n",
                app->emulation.backup_path,
                strerror(errno)
            ));
            gui_new_error(app, error_msg);
            return (true);
        }
    }
    return (false);
}


/*
** Load the BIOS/ROM into the emulator's memory and reset it.
**
** This function also sets the `qsave_path` and `backup_path` variables of `app.emulation`
** depending on the content of `app.emulation.game_path`.
*/
void
gui_reload_game(
    struct app *app
) {
    char *extension;
    size_t base_len;

    free(app->emulation.qsave_path);
    free(app->emulation.backup_path);

    extension = strrchr(app->emulation.game_path, '.');

    if (extension) {
        base_len = extension - app->emulation.game_path;
    } else {
        base_len = strlen(app->emulation.game_path);
    }

    hs_assert(-1 != asprintf(
        &app->emulation.qsave_path,
        "%.*s.hds",
        (int)base_len,
        app->emulation.game_path
    ));

    hs_assert(-1 != asprintf(
        &app->emulation.backup_path,
        "%.*s.sav",
        (int)base_len,
        app->emulation.game_path
    ));

    if (!gui_load_bios(app) && !gui_load_rom(app) && !gui_load_save(app)) {
        app->emulation.enabled = true;

        gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_RESET());
    }
    app->bg_color.x = 0.f;
    app->bg_color.y = 0.f;
    app->bg_color.z = 0.f;
    app->bg_color.w = 1.f;
}

void
gui_game_fullscreen(
    struct app *app
) {
    float game_scale;
    float rel_x;
    float rel_y;
    int width;
    int height;

    /* Resize the window to keep the correct aspect ratio */
    SDL_GetWindowSize(app->window, &width, &height);
    height = max(0, height - app->menubar_height);
    game_scale = min(width / (float)GBA_SCREEN_WIDTH, height / (float)GBA_SCREEN_HEIGHT);
    rel_x = (width  - (GBA_SCREEN_WIDTH  * game_scale)) * 0.5f;
    rel_y = (height - (GBA_SCREEN_HEIGHT * game_scale)) * 0.5f;

    igPushStyleVarVec2(ImGuiStyleVar_WindowPadding, (ImVec2){.x = 0, .y = 0});
    igPushStyleVarFloat(ImGuiStyleVar_WindowBorderSize, 0);

    igSetNextWindowPos(
        (ImVec2){
            .x = rel_x,
            .y = (float)app->menubar_height + rel_y,
        },
        ImGuiCond_Always,
        (ImVec2){.x = 0, .y = 0}
    );

    igSetNextWindowSize(
        (ImVec2){
            .x = GBA_SCREEN_WIDTH * game_scale,
            .y = GBA_SCREEN_HEIGHT * game_scale
        },
        ImGuiCond_Always
    );

    igBegin(
        "Game",
        NULL,
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysAutoResize |
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoDecoration |
        ImGuiWindowFlags_NoBackground
    );

    GLint last_texture;
    glGetIntegerv(GL_TEXTURE_BINDING_2D, &last_texture);

    glBindTexture(GL_TEXTURE_2D, app->game_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);

    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, GBA_SCREEN_WIDTH, GBA_SCREEN_HEIGHT, 0, GL_RGBA, GL_UNSIGNED_BYTE, (uint8_t *)app->emulation.gba->framebuffer);

    glBindTexture(GL_TEXTURE_2D, last_texture);

    igImage(
        (void *)(uintptr_t)app->game_texture,
        (ImVec2){.x = GBA_SCREEN_WIDTH * game_scale, .y = GBA_SCREEN_HEIGHT * game_scale},
        (ImVec2){.x = 0, .y = 0},
        (ImVec2){.x = 1, .y = 1},
        (ImVec4){.x = 1, .y = 1, .z = 1, .w = 1},
        (ImVec4){.x = 0, .y = 0, .z = 0, .w = 0}
    );

    igEnd();

    igPopStyleVar(2);
}

void
gui_game_handle_events(
    struct app *app,
    SDL_Event *event
) {
    switch (event->type) {
        case SDL_KEYDOWN:
            {
                switch (event->key.keysym.sym) {
                    case SDLK_UP:
                    case SDLK_w:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_UP, true)); break;
                    case SDLK_DOWN:
                    case SDLK_s:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_DOWN, true)); break;
                    case SDLK_LEFT:
                    case SDLK_a:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_LEFT, true)); break;
                    case SDLK_RIGHT:
                    case SDLK_d:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_RIGHT, true)); break;
                    case SDLK_p:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_A, true)); break;
                    case SDLK_l:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_B, true)); break;
                    case SDLK_e:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_L, true)); break;
                    case SDLK_o:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_R, true)); break;
                    case SDLK_BACKSPACE:        gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_SELECT, true)); break;
                    case SDLK_RETURN:           gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_START, true)); break;
                }
            }
            break;
        case SDL_KEYUP:
            {
                switch (event->key.keysym.sym) {
                    case SDLK_UP:
                    case SDLK_w:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_UP, false)); break;
                    case SDLK_DOWN:
                    case SDLK_s:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_DOWN, false)); break;
                    case SDLK_LEFT:
                    case SDLK_a:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_LEFT, false)); break;
                    case SDLK_RIGHT:
                    case SDLK_d:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_RIGHT, false)); break;
                    case SDLK_p:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_A, false)); break;
                    case SDLK_l:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_B, false)); break;
                    case SDLK_e:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_L, false)); break;
                    case SDLK_o:                gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_R, false)); break;
                    case SDLK_BACKSPACE:        gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_SELECT, false)); break;
                    case SDLK_RETURN:           gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_START, false)); break;
                    //case SDLK_F2:               sdl_take_screenshot(app); break;
                    case SDLK_F5:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_QUICKSAVE()); break;
                    case SDLK_F8:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_QUICKLOAD()); break;
                    default:
                        break;
                }
            }
            break;
        case SDL_CONTROLLERBUTTONDOWN:
            {
                switch (event->cbutton.button) {
                    case SDL_CONTROLLER_BUTTON_B:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_A, true)); break;
                    case SDL_CONTROLLER_BUTTON_A:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_B, true)); break;
                    case SDL_CONTROLLER_BUTTON_Y:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_A, true)); break;
                    case SDL_CONTROLLER_BUTTON_X:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_B, true)); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_LEFT:       gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_LEFT, true)); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_RIGHT:      gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_RIGHT, true)); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_UP:         gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_UP, true)); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_DOWN:       gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_DOWN, true)); break;
                    case SDL_CONTROLLER_BUTTON_LEFTSHOULDER:    gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_L, true)); break;
                    case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER:   gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_R, true)); break;
                    case SDL_CONTROLLER_BUTTON_START:           gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_START, true)); break;
                    case SDL_CONTROLLER_BUTTON_BACK:            gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_SELECT, true)); break;
                }
            }
            break;
        case SDL_CONTROLLERBUTTONUP:
            {
                switch (event->cbutton.button) {
                    case SDL_CONTROLLER_BUTTON_B:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_A, false)); break;
                    case SDL_CONTROLLER_BUTTON_A:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_B, false)); break;
                    case SDL_CONTROLLER_BUTTON_Y:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_A, false)); break;
                    case SDL_CONTROLLER_BUTTON_X:               gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_B, false)); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_LEFT:       gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_LEFT, false)); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_RIGHT:      gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_RIGHT, false)); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_UP:         gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_UP, false)); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_DOWN:       gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_DOWN, false)); break;
                    case SDL_CONTROLLER_BUTTON_LEFTSHOULDER:    gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_L, false)); break;
                    case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER:   gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_R, false)); break;
                    case SDL_CONTROLLER_BUTTON_START:           gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_START, false)); break;
                    case SDL_CONTROLLER_BUTTON_BACK:            gba_f2e_message_push(app->emulation.gba, NEW_MESSAGE_KEYINPUT(KEY_SELECT, false)); break;
#if SDL_VERSION_ATLEAST(2, 0, 14)
                    //case SDL_CONTROLLER_BUTTON_MISC1:           sdl_take_screenshot(app->emulation.gba); break;
#endif
                }
            }
        }
}