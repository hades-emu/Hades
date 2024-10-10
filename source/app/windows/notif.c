/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE

#include <cimgui.h>
#include "hades.h"
#include "app/app.h"
#include "compat.h"

#define NOTIFICATION_WIDTH              300.f
#define NOTIFICATION_PADDING_X          13.f
#define NOTIFICATION_PADDING_Y          13.f
#define NOTIFICATION_TOTAL_TIME_MS      3000
#define NOTIFICATION_FADE_TIME_MS       200

void
app_new_notification(
    struct app *app,
    enum app_notification_kind kind,
    char const *msg,
    ...
) {
    struct app_notification *notif;
    struct app_notification *n;
    char *formatted_msg;
    va_list va;

    va_start(va, msg);
    hs_assert(-1 != vasprintf(&formatted_msg, msg, va));
    va_end(va);

    notif = calloc(1, sizeof(*notif));
    hs_assert(notif);

    notif->kind = kind;
    notif->msg = formatted_msg;
    notif->timeout = hs_time() + 1000 * NOTIFICATION_TOTAL_TIME_MS;
    notif->fade_time_start = notif->timeout - 1000 * NOTIFICATION_FADE_TIME_MS;
    notif->next = NULL;

    // Push the notification at the end of `app->ui.notifications`.
    if (app->ui.notifications) {
        n = app->ui.notifications;
        while (n->next) {
            n = n->next;
        }
        n->next = notif;
    } else {
        app->ui.notifications = notif;
    }

    // Print the notification's messages to the log.
    switch (notif->kind) {
        case UI_NOTIFICATION_INFO:       logln(HS_INFO, "%s", formatted_msg); break;
        case UI_NOTIFICATION_SUCCESS:    logln(HS_INFO, "%s%s%s", g_light_green, formatted_msg, g_reset); break;
        case UI_NOTIFICATION_ERROR:      logln(HS_ERROR, "%s", formatted_msg); break;
    }
}

void
app_delete_notification(
    struct app_notification *notif
) {
    free(notif->msg);
    free(notif);
}

void
app_win_notifications(
    struct app *app
) {
    struct app_notification *notif;
    struct app_notification **prev;
    size_t offset;
    uint64_t now;
    size_t i;

    i = 0;
    offset = 0;
    now = hs_time();
    prev = &app->ui.notifications;
    notif = app->ui.notifications;
    while (notif) {
        char label[32];
        float alpha;

        snprintf(label, sizeof(label), "Notification##%zu", i);

        if (now >= notif->timeout) {
            alpha = 0.f;
        } else if (now >= notif->fade_time_start) {
            alpha = 1.f - (now - notif->fade_time_start) / (1000.f * NOTIFICATION_FADE_TIME_MS);
        } else {
            alpha = 1.f;
        }

        igSetNextWindowBgAlpha(alpha * 0.9);
        igSetNextWindowSizeConstraints(
            (ImVec2){.x = NOTIFICATION_WIDTH * app->ui.scale, .y = -1},
            (ImVec2){.x = NOTIFICATION_WIDTH * app->ui.scale, .y = -1},
            NULL,
            NULL
        );
        igSetNextWindowPos(
            (ImVec2){.x = app->ui.display.win.width - NOTIFICATION_PADDING_X * app->ui.scale, .y = app->ui.display.win.height - offset - NOTIFICATION_PADDING_Y * app->ui.scale},
            ImGuiCond_Always,
            (ImVec2){.x = 1., .y = 1.}
        );

        igBegin(
            label,
            NULL,
            ImGuiWindowFlags_NoDecoration
              | ImGuiWindowFlags_NoFocusOnAppearing
              | ImGuiWindowFlags_AlwaysAutoResize
              | ImGuiWindowFlags_NoNav
              | ImGuiWindowFlags_NoInputs
        );

        switch (notif->kind) {
            case UI_NOTIFICATION_INFO: {
                igText("Info");
                break;
            };
            case UI_NOTIFICATION_SUCCESS: {
                ImVec4 color;

                igColorConvertU32ToFloat4(&color, 0XFF55FF55);
                igTextColored(color, "Success");
                break;
            };
            case UI_NOTIFICATION_ERROR: {
                ImVec4 color;

                igColorConvertU32ToFloat4(&color, 0XFF5555FF);
                igTextColored(color, "Error");
                break;
            };
        }

        igSeparator();

        igTextWrapped(notif->msg);

        offset += igGetWindowHeight() + NOTIFICATION_PADDING_Y * app->ui.scale;

        igEnd();

        if (now >= notif->timeout) {
            *prev = notif->next;
            app_delete_notification(notif);
        }

        notif = notif->next;
        ++i;
    }
}
