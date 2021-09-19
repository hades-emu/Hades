/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "gba/core/arm.h"
#include "gba/core/thumb.h"
#include "gba/gba.h"
#include "utils/time.h"

/*
** Initialize the `gba` structure with sane, default values.
*/
void
gba_init(
    struct gba *gba
) {
    memset(gba, 0, sizeof(*gba));

    /* Initialize the ARM decoder */
    core_arm_decode_insns();
    core_thumb_decode_insns();

    pthread_mutex_init(&gba->message_queue[0].lock, NULL);
    pthread_mutex_init(&gba->message_queue[1].lock, NULL);

}

/*
** Reset the GBA system to its initial state.
*/
void
gba_reset(
    struct gba *gba
) {
    sched_cleanup(gba);

    sched_init(gba);
    mem_reset(&gba->memory);
    io_init(&gba->io);
    ppu_init(gba);
    core_init(gba);
}

/*
** Run the emulator, consuming messages that dictate what the emulator should do.
**
** Messages are used as a bi-directional communications between the frontend and the emulator.
**
** Those messages can be:
**   - A new key was pressed
**   - The user asked for a quickload/quicksave
**   - The emulator must run until the next frame
**   - The emulator must pause, reset, save the game, etc.
*/
void
gba_run(
    struct gba *gba
) {
    uint64_t last_measured_time;
    uint64_t accumulated_time;
    uint64_t time_per_frame;

    last_measured_time = hs_tick_count();
    accumulated_time = 0;
    time_per_frame = 0;
    while (true) {
        struct message_queue *mqueue;
        struct message *message;

        pthread_mutex_lock(&gba->message_queue[FRONT_TO_EMULATOR].lock);

        mqueue = &gba->message_queue[FRONT_TO_EMULATOR];
        message = mqueue->messages;
        while (mqueue->length) {
            switch (message->type) {
                case MESSAGE_EXIT: {
                    pthread_mutex_unlock(&gba->message_queue[FRONT_TO_EMULATOR].lock);
                    return ;
                };
                case MESSAGE_LOAD_BIOS: {
                    struct message_data *message_data;

                    message_data = (struct message_data *)message;
                    memset(gba->memory.bios, 0, BIOS_MASK);
                    memcpy(gba->memory.bios, message_data->data, min(message_data->size, BIOS_MASK));
                    if (message_data->cleanup) {
                        message_data->cleanup(message_data->data);
                    }
                    break;
                };
                case MESSAGE_LOAD_ROM: {
                    struct message_data *message_data;

                    message_data = (struct message_data *)message;
                    memset(gba->memory.rom, 0, CART_SIZE);
                    memcpy(gba->memory.rom, message_data->data, min(message_data->size, CART_SIZE));
                    if (message_data->cleanup) {
                        message_data->cleanup(message_data->data);
                    }
                    break;
                };
                case MESSAGE_LOAD_BACKUP: {
                    struct message_data *message_data;

                    message_data = (struct message_data *)message;
                    memset(gba->memory.backup_storage_data, 0, backup_storage_sizes[gba->memory.backup_storage_type]);
                    memcpy(
                        gba->memory.backup_storage_data,
                        message_data->data,
                        min(message_data->size, backup_storage_sizes[gba->memory.backup_storage_type])
                    );
                    if (message_data->cleanup) {
                        message_data->cleanup(message_data->data);
                    }
                    break;
                };
                case MESSAGE_BACKUP_TYPE: {
                    struct message_backup_type *message_backup_type;

                    message_backup_type = (struct message_backup_type *)message;
                    if (message_backup_type->type == BACKUP_AUTODETECT) {
                        mem_backup_storage_detect(gba);
                    }
                    mem_backup_storage_init(gba);
                    break;
                };
                case MESSAGE_RESET: {
                    gba_reset(gba);
                    break;
                };
                case MESSAGE_RUN: {
                    struct message_run *message_run;

                    message_run = (struct message_run *)message;
                    gba->state = GBA_STATE_RUN;
                    gba->speed = message_run->speed;
                    if (message_run->speed) {
                        time_per_frame = 1.f/59.737f * 1000.f * 1000.f / (float)gba->speed;
                        accumulated_time = 0;
                    } else {
                        time_per_frame = 0.f;
                    }
                    break;
                };
                case MESSAGE_PAUSE: {
                    gba->state = GBA_STATE_PAUSE;
                    break;
                };
                case MESSAGE_KEYINPUT: {
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
                    break;
                };
                case MESSAGE_QUICKLOAD: {
                    //quickload(gba, gba->quicksave_path);
                    break;
                };
                case MESSAGE_QUICKSAVE: {
                    //quicksave(gba, gba->quicksave_path);
                    break;
                };
            }
            mqueue->allocated_size -= message->size;
            --mqueue->length;
            message = (struct message *)((uint8_t *)message + message->size);
        }
        free(mqueue->messages);
        mqueue->messages = NULL;

        pthread_mutex_unlock(&gba->message_queue[FRONT_TO_EMULATOR].lock);

        if (gba->state == GBA_STATE_RUN) {
            sched_run_for(gba, CYCLES_PER_FRAME);
        }

        /* Limit FPS */
        if (gba->speed) {
            uint64_t now;

            now = hs_tick_count();
            accumulated_time += now - last_measured_time;
            last_measured_time = now;

            if (accumulated_time < time_per_frame) {
                hs_usleep(time_per_frame - accumulated_time);
                now = hs_tick_count();
                accumulated_time += now - last_measured_time;
                last_measured_time = now;
            }
            hs_assert(accumulated_time >= time_per_frame);
            accumulated_time -= time_per_frame;
        } else {
            last_measured_time = hs_tick_count();
            accumulated_time = 0;
        }
    }
}

/*
** Put the given message in the "front to emulator" queue.
*/
void
gba_f2e_message_push(
    struct gba *gba,
    struct message *message
) {
    size_t new_size;
    struct message_queue *mqueue;

    mqueue = &gba->message_queue[FRONT_TO_EMULATOR];
    pthread_mutex_lock(&gba->message_queue[FRONT_TO_EMULATOR].lock);

    new_size = mqueue->allocated_size + message->size;

    mqueue->messages = realloc(mqueue->messages, new_size);
    hs_assert(mqueue->messages);
    memcpy((uint8_t *)mqueue->messages + mqueue->allocated_size, message, message->size);

    mqueue->length += 1;
    mqueue->allocated_size = new_size;

    pthread_mutex_unlock(&gba->message_queue[FRONT_TO_EMULATOR].lock);
}