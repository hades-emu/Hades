/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <cimgui.h>
#include "app/app.h"

static char const * const cheats_kind_names[MENU_MAX] = {
    [RAW_CHEAT_KIND_PARV3] = "Action\nReplay",
    [RAW_CHEAT_KIND_GAMESHARK] = "Gameshark",
    [RAW_CHEAT_KIND_CODEBREAKER] = " Code\nBreaker",
};

#define CHEATS_FIELD_WIDTH_MIN                  (200.f)
#define CHEATS_FIELD_WIDTH_MAX                  (500.f)
#define CHEATS_FIELD_WIDTH_MIN_RATIO            (0.65f)
#define CHEATS_FIELD_RADIO_BUTTON_SNAP_WIDTH    150.0f

static
float
app_win_cheats_calculate_field_width(
    void
) {
    ImVec2 size;
    float t;

    igGetContentRegionAvail(&size);

    if (size.x <= CHEATS_FIELD_WIDTH_MIN) {
        return size.x;
    }

    if (size.x >= CHEATS_FIELD_WIDTH_MAX) {
        return size.x * CHEATS_FIELD_WIDTH_MIN_RATIO;
    }

    t = (size.x - CHEATS_FIELD_WIDTH_MIN) / (CHEATS_FIELD_WIDTH_MAX - CHEATS_FIELD_WIDTH_MIN);
    return size.x * (1.0f - t * (1.0f - CHEATS_FIELD_WIDTH_MIN_RATIO));
}

static
void
app_win_cheats_list(
    struct app *app
) {
    ImGuiViewport *vp;
    ImVec2 size;
    size_t i;

    vp = igGetMainViewport();

    igBeginChild_Str("##CheatsList", (ImVec2){ vp->WorkSize.x / 4.f, -igGetFrameHeightWithSpacing()}, ImGuiChildFlags_Borders, ImGuiWindowFlags_None);

    for (i = 0; i < app->cheats.len; ++i) {
        struct gba_cheat_raw *raw;

        raw = &app->cheats.list[i];

        igPushID_Int(i);

        if (igSelectable_Bool("##Name", i == app->ui.cheats.selected, ImGuiSelectableFlags_None, (ImVec2){ 0.f, 0.f})) {
            app->ui.cheats.selected = i;
        }

        igSameLine(0.0f, 0.0f);

        if (raw->enabled) {
            if (!raw->compilation.finished) {
                cheat_parse(raw);
            }

            if (raw->compilation.success) {
                ImVec4 color;

                igColorConvertU32ToFloat4(&color, 0xFF50AF4C);
                igTextColored(color, "o");
            } else {
                ImVec4 color;

                igColorConvertU32ToFloat4(&color, 0xFF5053EF);
                igTextColored(color, "x");
            }
        } else {
            ImVec4 color;

            igColorConvertU32ToFloat4(&color, 0xFF0098FF);
            igTextColored(color, "!");
        }

        igSameLine(0.0f, 0.0f);
        igText(" %s", app->cheats.list[i].name);

        igPopID();
    }

    if (i > 0) {
        igSeparator();
    }

    igGetContentRegionAvail(&size);
    if (igButton("New", (ImVec2){size.x, 0.f})) {
        struct gba_cheat_raw *cheat;

        app->cheats.len += 1;
        app->cheats.list = realloc(app->cheats.list, app->cheats.len * sizeof(struct gba_cheat_raw));
        hs_assert(app->cheats.list);

        cheat = &app->cheats.list[app->cheats.len - 1];
        memset(cheat, 0, sizeof(struct gba_cheat_raw));

        cheat->enabled = true;
        cheat->kind = RAW_CHEAT_KIND_PARV3;
        strcpy(cheat->name, "New Cheat");

        app->ui.cheats.selected = app->cheats.len - 1;
    }

    igEndChild();
}

static
void
app_win_cheats_content(
    struct app *app
) {
    ImGuiViewport *vp;

    vp = igGetMainViewport();

    igBeginChild_Str("##CheatsContent", (ImVec2){ 0.f, -igGetFrameHeightWithSpacing()}, ImGuiChildFlags_Borders, ImGuiWindowFlags_None);
    if (app->ui.cheats.selected < app->cheats.len) {
        if (igBeginTable("##CheatsContentTable", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
            struct gba_cheat_raw *raw;

            raw = &app->cheats.list[app->ui.cheats.selected];

            igTableSetupColumn("##CheatsContentLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
            igTableSetupColumn("##CheatsContentValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

            igTableNextRow(ImGuiTableRowFlags_None, 0.f);
            igTableNextColumn();
            igTextWrapped("Enabled");

            igTableNextColumn();
            igCheckbox("##Enabled", &raw->enabled);

            igTableNextRow(ImGuiTableRowFlags_None, 0.f);
            igTableNextColumn();
            igTextWrapped("Name");

            igTableNextColumn();
            igInputTextEx("##Name", "Cheat Name", raw->name, sizeof(raw->name), (ImVec2){app_win_cheats_calculate_field_width(), 0}, ImGuiInputTextFlags_None, NULL, NULL);

            igTableNextRow(ImGuiTableRowFlags_None, 0.f);
            igTableNextColumn();
            igTextWrapped("Type");

            igTableNextColumn();
            {
                float seg_width;
                ImVec2 size;
                bool snap;
                int i;

                igGetContentRegionAvail(&size);
                snap = size.x <= CHEATS_FIELD_RADIO_BUTTON_SNAP_WIDTH;
                seg_width = snap ? -0.0f : (app_win_cheats_calculate_field_width() - igGetStyle()->ItemSpacing.x * (RAW_CHEAT_KIND_MAX - 1)) / RAW_CHEAT_KIND_MAX;

                igPushStyleVar_Vec2(ImGuiStyleVar_SelectableTextAlign, (ImVec2){ 0.5f, 0.5f });

                for (i = 0; i < RAW_CHEAT_KIND_MAX; ++i) {
                    if (i > 0 && !snap) {
                        igSameLine(0.0f, -1.0f);
                    }

                    igBeginDisabled(i > 0); // TODO FIXME: Only PARV3 is availalbe right now.

                    if (igSelectable_Bool(
                        cheats_kind_names[i],
                        raw->kind == i,
                        ImGuiSelectableFlags_NoPadWithHalfSpacing,
                        (ImVec2){ seg_width, igGetFrameHeight() * 2.f }
                    )) {
                        raw->kind = i;
                        cheat_parse(raw);
                    }

                    igEndDisabled();
                }

                igPopStyleVar(1);
            }

            igTableNextRow(ImGuiTableRowFlags_None, 0.f);
            igTableNextColumn();
            igTextWrapped("Status");

            igTableNextColumn();

            if (raw->enabled) {
                if (!raw->compilation.finished) {
                    cheat_parse(raw);
                }

                if (raw->compilation.success) {
                    ImVec4 color;

                    igColorConvertU32ToFloat4(&color, 0xFF50AF4C);
                    igTextColored(color, "No error detected.");
                } else {
                    ImVec4 color;

                    igColorConvertU32ToFloat4(&color, 0xFF5053EF);
                    igTextColored(color, "Error: %s.", raw->compilation.error);
                }
            } else {
                ImVec4 color;

                igColorConvertU32ToFloat4(&color, 0xFF0098FF);
                igTextColored(color, "Cheat is disabled.");
            }


            igTableNextRow(ImGuiTableRowFlags_None, 0.f);
            igTableNextColumn();

            igTextWrapped("Code");
            igTableNextColumn();
            if (igInputTextEx(
                    "##Code",
                    "00000000 00000000",
                    raw->code,
                    sizeof(raw->code),
                    (ImVec2){app_win_cheats_calculate_field_width(), -1},
                    ImGuiInputTextFlags_Multiline,
                    NULL,
                    NULL
                )
            ) {
                cheat_parse(raw);
            }

            igEndTable();
        }
    } else {
        char const *text;

        text = "No cheat selected.";
        ImVec2 available;
        ImVec2 textSize;

        igGetContentRegionAvail(&available);
        igCalcTextSize(&textSize, text, NULL, false, -1);

        igSetCursorPos((ImVec2){
            igGetCursorPosX() + (available.x - textSize.x) * 0.5f,
            igGetCursorPosY() + (available.y - textSize.y) * 0.5f
        });

        igText(text);
    }
    igEndChild();
}

void
app_win_cheats(
    struct app *app
) {
    ImGuiViewport *vp;

    // Close this window without saving if there's no game running.
    // This can happen, for example, if the keybind to stop the current game is pressed while the cheats are being edited.
    if (!app->emulation.is_started) {
        app->ui.main_window = MAIN_WINDOW_NONE;
        return;
    }

    vp = igGetMainViewport();

    igSetNextWindowPos(vp->WorkPos, ImGuiCond_Always, (ImVec2){0.f, 0.f});
    igSetNextWindowSize(vp->WorkSize, ImGuiCond_Always);

    if (igBegin(
        "Cheats",
        NULL,
        ImGuiWindowFlags_None
          | ImGuiWindowFlags_NoMove
          | ImGuiWindowFlags_NoResize
          | ImGuiWindowFlags_AlwaysAutoResize
          | ImGuiWindowFlags_NoTitleBar
    )) {
        igBeginGroup();
        app_win_cheats_list(app);
        igEndGroup();

        igSameLine(0.0f, -1.0f);

        igBeginGroup();

        app_win_cheats_content(app);

        if (igButton("Save", (ImVec2){ 0.f, 0.f})) {
            app_cheats_save(app);
        }

        igSameLine(0.0f, -1.0f);
        if (igButton("Exit", (ImVec2){ 0.f, 0.f})) {
            app->ui.main_window = MAIN_WINDOW_NONE;
            app_cheats_save(app);
        }

        igSameLine(0.0f, -1.0f);
        if (igButton("Delete", (ImVec2){ 0.f, 0.f})) {
            memmove(
                &app->cheats.list[app->ui.cheats.selected],
                &app->cheats.list[app->ui.cheats.selected + 1],
                (app->cheats.len - app->ui.cheats.selected - 1) * sizeof(struct gba_cheat_raw)
            );

            app->cheats.len -= 1;
            app->cheats.list = realloc(app->cheats.list, app->cheats.len * sizeof(struct gba_cheat_raw));
            hs_assert(app->cheats.list);

            app_cheats_save(app);
        }


        igEndGroup();

        igEnd();
    }
}
