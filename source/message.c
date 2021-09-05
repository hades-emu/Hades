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
#include "message.h"

/*
** Messages are used by the frontend thread (typically the GUI) to communicate input
** and intentions to the logic thread.
**
** Those messages can be:
**   - A new key was pressed
**   - The user asked for a quickload/quicksave
**   - The user changed a setting
** etc.
*/

void
message_new(
    struct gba *gba,
    struct message *message
) {
    size_t new_size;
    struct message_queue *mqueue;

    mqueue = &gba->message_queue;
    pthread_mutex_lock(&gba->message_queue_mutex);

    new_size = mqueue->size + message->size;

    mqueue->messages = realloc(mqueue->messages, new_size);
    hs_assert(mqueue->messages);
    memcpy((uint8_t *)mqueue->messages + mqueue->size, message, message->size);

    mqueue->nb_messages += 1;
    mqueue->size = new_size;

    pthread_mutex_unlock(&gba->message_queue_mutex);
}

void
message_handle_all(
    struct gba *gba
) {
    struct message_queue *mqueue;
    struct message *message;

    pthread_mutex_lock(&gba->message_queue_mutex);

    mqueue = &gba->message_queue;
    message = mqueue->messages;
    while (mqueue->nb_messages) {
        switch (message->type) {
            case MESSAGE_KEYINPUT:
                {
                    struct message_keyinput *message_keyinput;

                    message_keyinput = (struct message_keyinput *)message;
                    switch (message_keyinput->key) {
                        case KEY_A:         gba->io.keyinput.a = !message_keyinput->pressed; break;
                        case KEY_B:         gba->io.keyinput.b = !message_keyinput->pressed; break;
                        case KEY_L:         gba->io.keyinput.l = !message_keyinput->pressed; break;
                        case KEY_R:         gba->io.keyinput.r = !message_keyinput->pressed; break;
                        case KEY_UP:        gba->io.keyinput.up = !message_keyinput->pressed; break;
                        case KEY_DOWN:      gba->io.keyinput.down = !message_keyinput->pressed; break;
                        case KEY_RIGHT:     gba->io.keyinput.right = !message_keyinput->pressed; break;
                        case KEY_LEFT:      gba->io.keyinput.left = !message_keyinput->pressed; break;
                        case KEY_START:     gba->io.keyinput.start = !message_keyinput->pressed; break;
                        case KEY_SELECT:    gba->io.keyinput.select = !message_keyinput->pressed; break;
                    };

                    if (message_keyinput->pressed) {
                        core_trigger_irq(gba, IRQ_KEYPAD);
                    }

                    break;
                }
            case MESSAGE_QUICKLOAD:
                quickload(gba, gba->quicksave_path);
                break;
            case MESSAGE_QUICKSAVE:
                quicksave(gba, gba->quicksave_path);
                break;
        }
        mqueue->size -= message->size;
        --mqueue->nb_messages;
        message = (struct message *)((uint8_t *)message + message->size);
    }

    free(mqueue->messages);
    mqueue->messages = NULL;

    pthread_mutex_unlock(&gba->message_queue_mutex);
}