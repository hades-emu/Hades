/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE

#include <cimgui.h>
#include "hades.h"
#include "app/app.h"

/*
** Recalculate the game inner and outer game area based on the window area and the desired aspect ratio.
*/
void
app_win_game_refresh_game_area(
    struct app *app
) {
    app->ui.display.game.outer.x = 0;
    app->ui.display.game.outer.y = 0;

    // Ensure the outer window is below the menubar
    if (app->settings.video.menubar_mode == MENUBAR_MODE_PINNED) {
        app->ui.display.game.outer.y += app->ui.menubar.size.y * app->ui.menubar.visibility;
    }

    app->ui.display.game.outer.width = app->ui.display.win.width - app->ui.display.game.outer.x;
    app->ui.display.game.outer.height = app->ui.display.win.height - app->ui.display.game.outer.y;

    // Apply the aspect ratio setting
    switch (app->settings.video.aspect_ratio) {
        case ASPECT_RATIO_BORDERS: {
            float game_scale;

            game_scale = min(
                app->ui.display.game.outer.width / (float)GBA_SCREEN_WIDTH,
                app->ui.display.game.outer.height / (float)GBA_SCREEN_HEIGHT
            );

            app->ui.display.game.inner.x = app->ui.display.game.outer.x + (app->ui.display.game.outer.width  - (GBA_SCREEN_WIDTH  * game_scale)) * 0.5f;
            app->ui.display.game.inner.y = app->ui.display.game.outer.y + (app->ui.display.game.outer.height - (GBA_SCREEN_HEIGHT * game_scale)) * 0.5f;
            app->ui.display.game.inner.width = GBA_SCREEN_WIDTH * game_scale;
            app->ui.display.game.inner.height = GBA_SCREEN_HEIGHT * game_scale;
            break;
        };
        case ASPECT_RATIO_STRETCH: {
            // Stretch means the inner and outer game area are the same.
            app->ui.display.game.inner.x = app->ui.display.game.outer.x;
            app->ui.display.game.inner.y = app->ui.display.game.outer.y;
            app->ui.display.game.inner.width = app->ui.display.game.outer.width;
            app->ui.display.game.inner.height = app->ui.display.game.outer.height;
            break;
        };
        default: {
            panic(HS_INFO, "Invalid aspect ratio %u", app->settings.video.aspect_ratio);
            break;
        };
    }
}

static
void
app_win_game_pause_text(
    struct app const *app
) {
    igPushFont(NULL, igGetFontSize() * 3.0);
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
app_win_game(
    struct app *app
) {
    ImTextureRef *out_texture_ref;
    GLuint in_texture;
    GLuint out_texture;
    float tint;

    // Adjust the tint if the game is paused and we wanna show the pause overlay
    tint = !app->emulation.is_running && !app->settings.general.window.hide_pause_overlay ? 0.1 : 1.0;

    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, app->gfx.game_texture);

    pthread_mutex_lock(&app->emulation.gba->shared_data.framebuffer.lock);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, GBA_SCREEN_WIDTH, GBA_SCREEN_HEIGHT, 0, GL_RGBA, GL_UNSIGNED_BYTE, (uint8_t *)app->emulation.gba->shared_data.framebuffer.data);
    pthread_mutex_unlock(&app->emulation.gba->shared_data.framebuffer.lock);

    out_texture = app->gfx.game_texture;

    glBindVertexArray(app->gfx.vao);
    glBindFramebuffer(GL_FRAMEBUFFER, app->gfx.fbo);

    // Apply the Pixel Color Effect
    if (app->gfx.pixel_color_program != 0) {
        in_texture = out_texture;
        out_texture = app->gfx.pixel_color_texture;

        // Set the viewport
        glViewport(0, 0, GBA_SCREEN_WIDTH, GBA_SCREEN_HEIGHT);

        // Set the input and output texture
        glBindTexture(GL_TEXTURE_2D, in_texture);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, out_texture, 0);

        // Set the shader to use
        glUseProgram(app->gfx.pixel_color_program);

        // Draw
        glDrawArrays(GL_TRIANGLES, 0, 6);
    }

    // Apply the Pixel Scaling Effect
    if (app->gfx.pixel_scaling_program != 0) {
        in_texture = out_texture;
        out_texture = app->gfx.pixel_scaling_texture;

        // Set the viewport
        glViewport(0, 0, GBA_SCREEN_WIDTH * app->gfx.pixel_scaling_size, GBA_SCREEN_HEIGHT * app->gfx.pixel_scaling_size);

        // Set the input and output texture
        glBindTexture(GL_TEXTURE_2D, in_texture);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, out_texture, 0);

        // Set the shader to use
        glUseProgram(app->gfx.pixel_scaling_program);

        // Draw
        glDrawArrays(GL_TRIANGLES, 0, 6);
    }

    glUseProgram(0);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glBindVertexArray(0);
    glBindTexture(GL_TEXTURE_2D, 0);

    igPushStyleVar_Vec2(ImGuiStyleVar_WindowPadding, (ImVec2){.x = 0, .y = 0});
    igPushStyleVar_Float(ImGuiStyleVar_WindowBorderSize, 0);

    igSetNextWindowPos(
        (ImVec2){.x = app->ui.display.game.inner.x, .y = app->ui.display.game.inner.y},
        ImGuiCond_Always,
        (ImVec2){.x = 0, .y = 0}
    );
    igSetNextWindowSize(
        (ImVec2){.x = app->ui.display.game.inner.width, .y = app->ui.display.game.inner.height},
        ImGuiCond_Always
    );

    igBegin(
        "Game",
        NULL,
        ImGuiWindowFlags_NoScrollWithMouse
          | ImGuiWindowFlags_AlwaysAutoResize
          | ImGuiWindowFlags_NoDecoration
          | ImGuiWindowFlags_NoBackground
          | ImGuiWindowFlags_NoBringToFrontOnFocus
    );

    out_texture_ref = ImTextureRef_ImTextureRef_TextureID(out_texture);

    igImageWithBg(
        *out_texture_ref,
        (ImVec2){.x = app->ui.display.game.inner.width, .y = app->ui.display.game.inner.height},
        (ImVec2){.x = 0, .y = 0},
        (ImVec2){.x = 1, .y = 1},
        (ImVec4){.x = 0, .y = 0, .z = 0, .w = 0},
        (ImVec4){.x = tint, .y = tint, .z = tint, .w = 1}
    );

    ImTextureRef_destroy(out_texture_ref);

    if (!app->emulation.is_running && !app->settings.general.window.hide_pause_overlay) {
        app_win_game_pause_text(app);
    }

    igEnd();

    igPopStyleVar(2);
}
