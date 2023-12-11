/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS

#include <cimgui.h>
#include "hades.h"
#include "app.h"
#include "gui/gui.h"

static
void
gui_win_game_pause_text(
    struct app *app
) {
    igPushFont(app->ui.fonts.big);
    {
        char const *text;
        ImVec2 text_size;
        ImVec2 text_pos;
        ImVec2 win_size;

        text = "- GAME PAUSED -";

        igGetWindowSize(&win_size);
        igCalcTextSize(&text_size, text, NULL, false, -1.0f);

        text_pos.x = (win_size.x - text_size.x) / 2.f;
        text_pos.y = (win_size.y - text_size.y) / 2.f;
        igSetCursorPos(text_pos);
        igText(text);
    }
    igPopFont();
}

void
gui_win_game(
    struct app *app
) {
    float game_pos_x;
    float game_pos_y;
    float game_size_x;
    float game_size_y;
    float tint;

    // Adjust the tint if the game is paused
    tint = app->emulation.is_running ? 1.0 : 0.1;

    if (!app->gfx.active_programs_length) {
        // If there's no shaders loaded, we shortcut the pipeline and simply load the game's framebuffer in the corresponding texture

        glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, app->gfx.game_texture_out);

        pthread_mutex_lock(&app->emulation.gba->shared_data.framebuffer.lock);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, GBA_SCREEN_WIDTH, GBA_SCREEN_HEIGHT, 0, GL_RGBA, GL_UNSIGNED_BYTE, (uint8_t *)app->emulation.gba->shared_data.framebuffer.data);
        pthread_mutex_unlock(&app->emulation.gba->shared_data.framebuffer.lock);

        glBindTexture(GL_TEXTURE_2D, 0);
    } else {
        size_t i;

        glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, app->gfx.game_texture_in);

        pthread_mutex_lock(&app->emulation.gba->shared_data.framebuffer.lock);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, GBA_SCREEN_WIDTH, GBA_SCREEN_HEIGHT, 0, GL_RGBA, GL_UNSIGNED_BYTE, (uint8_t *)app->emulation.gba->shared_data.framebuffer.data);
        pthread_mutex_unlock(&app->emulation.gba->shared_data.framebuffer.lock);

        glViewport(0, 0, GBA_SCREEN_WIDTH, GBA_SCREEN_HEIGHT);
        glBindVertexArray(app->gfx.vao);
        glBindFramebuffer(GL_FRAMEBUFFER, app->gfx.fbo);

        for (i = 0; i < app->gfx.active_programs_length; ++i) {
            GLuint target_texture;

            glUseProgram(app->gfx.active_programs[i]);
            if (i == app->gfx.active_programs_length - 1) {
                target_texture = app->gfx.game_texture_out;
            } else {
                target_texture = app->gfx.game_texture_in;
            }

            glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, target_texture, 0);
            glDrawArrays(GL_TRIANGLES, 0, 6);
        }

        glUseProgram(0);
        glBindFramebuffer(GL_FRAMEBUFFER, 0);
        glBindVertexArray(0);
        glBindTexture(GL_TEXTURE_2D, 0);
    }

    /* Resize the game to keep the correct aspect ratio */
    switch (app->video.aspect_ratio) {
        case ASPECT_RATIO_RESIZE:
        case ASPECT_RATIO_BORDERS: {
            float game_scale;

            game_scale = min(app->ui.game.width / (float)GBA_SCREEN_WIDTH, app->ui.game.height / (float)GBA_SCREEN_HEIGHT);
            game_pos_x = (app->ui.game.width  - (GBA_SCREEN_WIDTH  * game_scale)) * 0.5f;
            game_pos_y = (app->ui.game.height - (GBA_SCREEN_HEIGHT * game_scale)) * 0.5f;
            game_size_x = GBA_SCREEN_WIDTH * game_scale;
            game_size_y = GBA_SCREEN_HEIGHT * game_scale;
            break;
        };
        case ASPECT_RATIO_STRETCH:
        default: {
            game_pos_x = 0;
            game_pos_y = 0;
            game_size_x = app->ui.game.width;
            game_size_y = app->ui.game.height;
            break;
        };
    }

    igPushStyleVarVec2(ImGuiStyleVar_WindowPadding, (ImVec2){.x = 0, .y = 0});
    igPushStyleVarFloat(ImGuiStyleVar_WindowBorderSize, 0);

    igSetNextWindowPos((ImVec2){.x = game_pos_x, .y = (float)app->ui.menubar_size.y + game_pos_y}, ImGuiCond_Always, (ImVec2){.x = 0, .y = 0});
    igSetNextWindowSize((ImVec2){.x = game_size_x, .y = game_size_y}, ImGuiCond_Always);

    igBegin(
        "Game",
        NULL,
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysAutoResize |
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoDecoration |
        ImGuiWindowFlags_NoBackground
    );

    igImage(
        (void *)(uintptr_t)app->gfx.game_texture_out,
        (ImVec2){.x = game_size_x, .y = game_size_y},
        (ImVec2){.x = 0, .y = 0},
        (ImVec2){.x = 1, .y = 1},
        (ImVec4){.x = tint, .y = tint, .z = tint, .w = 1},
        (ImVec4){.x = 0, .y = 0, .z = 0, .w = 0}
    );

    if (!app->emulation.is_running) {
        gui_win_game_pause_text(app);
    }

    igEnd();

    igPopStyleVar(2);
}
