/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba.h"
#include "event.h"

/*
** Event are used by the frontend thread (typically the GUI) to communicate input
** and intentions to the logic thread.
**
** Those events can be:
**   - A new key was pressed
**   - The user asked for a quickload/quicksave
**   - The user changed a setting
** etc.
*/

void
event_new(
    struct gba *gba,
    struct event *event
) {
    size_t new_size;
    struct event_queue *equeue;

    equeue = &gba->event_queue;
    pthread_mutex_lock(&gba->event_queue_mutex);

    new_size = equeue->size + event->size;

    equeue->events = realloc(equeue->events, new_size);
    hs_assert(equeue->events);
    memcpy((uint8_t *)equeue->events + equeue->size, event, event->size);

    equeue->nb_events += 1;
    equeue->size = new_size;

    pthread_mutex_unlock(&gba->event_queue_mutex);
}

void
event_handle_all(
    struct gba *gba
) {
    struct event_queue *equeue;
    struct event *event;

    pthread_mutex_lock(&gba->event_queue_mutex);

    equeue = &gba->event_queue;
    event = equeue->events;
    while (equeue->nb_events) {
        switch (event->type) {
            case EVENT_KEYINPUT:
                {
                    struct event_keyinput *event_keyinput;

                    event_keyinput = (struct event_keyinput *)event;
                    switch (event_keyinput->key) {
                        case KEY_A:         gba->io.keyinput.a = !event_keyinput->pressed; break;
                        case KEY_B:         gba->io.keyinput.b = !event_keyinput->pressed; break;
                        case KEY_L:         gba->io.keyinput.l = !event_keyinput->pressed; break;
                        case KEY_R:         gba->io.keyinput.r = !event_keyinput->pressed; break;
                        case KEY_UP:        gba->io.keyinput.up = !event_keyinput->pressed; break;
                        case KEY_DOWN:      gba->io.keyinput.down = !event_keyinput->pressed; break;
                        case KEY_RIGHT:     gba->io.keyinput.right = !event_keyinput->pressed; break;
                        case KEY_LEFT:      gba->io.keyinput.left = !event_keyinput->pressed; break;
                        case KEY_START:     gba->io.keyinput.start = !event_keyinput->pressed; break;
                        case KEY_SELECT:    gba->io.keyinput.select = !event_keyinput->pressed; break;
                    };

                    if (event_keyinput->pressed) {
                        core_trigger_irq(gba, IRQ_KEYPAD);
                    }

                    break;
                }
            case EVENT_QUICKLOAD:
                load_state(gba, gba->save_path);
                break;
            case EVENT_QUICKSAVE:
                save_state(gba, gba->save_path);
                break;
        }
        equeue->size -= event->size;
        --equeue->nb_events;
        event = (struct event *)((uint8_t *)event + event->size);
    }

    free(equeue->events);
    equeue->events = NULL;

    pthread_mutex_unlock(&gba->event_queue_mutex);
}