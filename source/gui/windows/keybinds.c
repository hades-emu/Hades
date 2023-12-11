/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <cimgui.h>
#include "hades.h"
#include "app.h"
#include "gui/gui.h"

char const * const binds_pretty_name[] = {
    [BIND_GBA_A] = "A",
    [BIND_GBA_B] = "B",
    [BIND_GBA_L] = "L",
    [BIND_GBA_R] = "R",
    [BIND_GBA_UP] = "Up",
    [BIND_GBA_DOWN] = "Down",
    [BIND_GBA_LEFT] = "Left",
    [BIND_GBA_RIGHT] = "Right",
    [BIND_GBA_START] = "Start",
    [BIND_GBA_SELECT] = "Select",

    [BIND_EMULATOR_SPEED_X1] = "Speed x1",
    [BIND_EMULATOR_SPEED_X2] = "Speed x2",
    [BIND_EMULATOR_SPEED_X3] = "Speed x3",
    [BIND_EMULATOR_SPEED_X4] = "Speed x4",
    [BIND_EMULATOR_SPEED_X5] = "Speed x5",
    [BIND_EMULATOR_SPEED_MAX_TOGGLE] = "Speed Max (Toggle)",
    [BIND_EMULATOR_SPEED_MAX_HOLD] = "Speed Max (Hold)",
    [BIND_EMULATOR_SCREENSHOT] = "Screenshot",
    [BIND_EMULATOR_QUICKSAVE] = "Quicksave",
    [BIND_EMULATOR_QUICKLOAD] = "Quickload",
    [BIND_EMULATOR_PAUSE] = "Pause",
    [BIND_EMULATOR_RESET] = "Reset",
};

char const * const binds_slug[] = {
    [BIND_GBA_A] = "a",
    [BIND_GBA_B] = "b",
    [BIND_GBA_L] = "l",
    [BIND_GBA_R] = "r",
    [BIND_GBA_UP] = "up",
    [BIND_GBA_DOWN] = "down",
    [BIND_GBA_LEFT] = "left",
    [BIND_GBA_RIGHT] = "right",
    [BIND_GBA_START] = "start",
    [BIND_GBA_SELECT] = "select",

    [BIND_EMULATOR_SPEED_X1] = "speed_x1",
    [BIND_EMULATOR_SPEED_X2] = "speed_x2",
    [BIND_EMULATOR_SPEED_X3] = "speed_x3",
    [BIND_EMULATOR_SPEED_X4] = "speed_x4",
    [BIND_EMULATOR_SPEED_X5] = "speed_x5",
    [BIND_EMULATOR_SPEED_MAX_TOGGLE] = "speed_max_toggle",
    [BIND_EMULATOR_SPEED_MAX_HOLD] = "speed_max_hold",
    [BIND_EMULATOR_SCREENSHOT] = "screenshot",
    [BIND_EMULATOR_QUICKSAVE] = "quicksave",
    [BIND_EMULATOR_QUICKLOAD] = "quickload",
    [BIND_EMULATOR_PAUSE] = "pause",
    [BIND_EMULATOR_RESET] = "reset",
};

void
gui_win_keybinds_editor(
    struct app *app
) {
    if (app->ui.keybindings_editor.open) {
        app->ui.keybindings_editor.open = false;
        igOpenPopup("Keybindings Editor", ImGuiPopupFlags_None);
    }

    app->ui.keybindings_editor.visible = false;

    // Always center the modal
    igSetNextWindowPos(
        (ImVec2){.x = app->ui.ioptr->DisplaySize.x * 0.5f, .y = app->ui.ioptr->DisplaySize.y * 0.5f},
        ImGuiCond_Always,
        (ImVec2){.x = 0.5f, .y = 0.5f}
    );

    if (igBeginPopupModal(
        "Keybindings Editor",
        NULL,
        ImGuiWindowFlags_Popup
          | ImGuiWindowFlags_Modal
          | ImGuiWindowFlags_NoResize
          | ImGuiWindowFlags_NoMove
          | ImGuiWindowFlags_NoTitleBar
          | ImGuiWindowFlags_AlwaysAutoResize
          | ImGuiWindowFlags_NoNavInputs
          | ImGuiWindowFlags_NoNavFocus
    )) {
        size_t bind;

        app->ui.keybindings_editor.visible = true;

        for (bind = BIND_MIN; bind < BIND_MAX; ++bind) {
            size_t j;


            if (bind == BIND_GBA_MIN || bind == BIND_EMULATOR_MIN) {
                igSpacing();
                igSpacing();

                if (bind == BIND_GBA_MIN) {
                    igText(" GBA");
                    igSameLine(0, igGetFontSize() * 13.5f);
                } else if (bind == BIND_EMULATOR_MIN) {
                    igText(" Hades");
                    igSameLine(0, igGetFontSize() * 12.5f);
                }

                igText("Keyboard");
                igSameLine(0, igGetFontSize() * 10.f);
                igText("Controller");


                igSpacing();
                igSeparator();
                igSpacing();
            }

            igText("  %-18s ", binds_pretty_name[bind]);

            for (j = 0; j < 4; ++j) {
                SDL_GameControllerButton *controller_target;
                SDL_Keycode *keyboard_target;
                char const *key_name;
                char label[32];

                key_name = NULL;
                keyboard_target = NULL;
                controller_target = NULL;

                switch (j) {
                    case 0: {
                        igSameLine(0, igGetFontSize() * 0.5f);
                        key_name = SDL_GetKeyName(app->binds.keyboard[bind]);
                        keyboard_target = &app->binds.keyboard[bind];
                        break;
                    };
                    case 1: {
                        igSameLine(0, igGetFontSize() * 0.5f);
                        key_name = SDL_GetKeyName(app->binds.keyboard_alt[bind]);
                        keyboard_target = &app->binds.keyboard_alt[bind];
                        break;
                    };
                    case 2: {
                        igSameLine(0, igGetFontSize() * 2.f);
                        key_name = SDL_GameControllerGetStringForButton(app->binds.controller[bind]);
                        controller_target = &app->binds.controller[bind];
                        break;
                    };
                    case 3: {
                        igSameLine(0, igGetFontSize() * 0.5f);
                        key_name = SDL_GameControllerGetStringForButton(app->binds.controller_alt[bind]);
                        controller_target = &app->binds.controller_alt[bind];
                        break;
                    };
                }

                if (
                       (keyboard_target && keyboard_target == app->ui.keybindings_editor.keyboard_target)
                    || (controller_target && controller_target == app->ui.keybindings_editor.controller_target)
                ) {
                    snprintf(label, sizeof(label), ">> %s <<##%zu", key_name ? key_name : " ", bind * 10 + j);
                } else {
                    snprintf(label, sizeof(label), "%s##%zu", key_name ? key_name : "", bind * 10 + j);
                }

                if (igButton(label, (ImVec2){.x = igGetFontSize() * 6.f, .y = igGetFontSize() * 1.5f})) {
                    app->ui.keybindings_editor.keyboard_target = keyboard_target;
                    app->ui.keybindings_editor.controller_target = controller_target;
                }
            }

            igSameLine(0, igGetFontSize() * 0.5f);
            igText(" ");
        }

        igSpacing();
        igSpacing();

        if (igButton("Close", (ImVec2){.x = igGetFontSize() * 4.f, .y = igGetFontSize() * 1.5f})) {
            igCloseCurrentPopup();
        }

        igEndPopup();
    }
}
