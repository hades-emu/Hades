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
            igInputTextEx("##Name", "Cheat Name", raw->name, sizeof(raw->name), (ImVec2){0, 0}, ImGuiInputTextFlags_None, NULL, NULL);

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
                    (ImVec2){0, -1},
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
