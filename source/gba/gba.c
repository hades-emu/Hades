/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "compat.h"
#include "gba/core/arm.h"
#include "gba/core/thumb.h"
#include "gba/gba.h"
#include "gba/db.h"

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

    pthread_mutex_init(&gba->message_queue.lock, NULL);
    pthread_cond_init(&gba->message_queue.ready, NULL);
}

/*
** Reset the GBA system to its initial state.
*/
static
void
gba_reset(
    struct gba *gba
) {
    gba->started = false;
    gba->state = GBA_STATE_PAUSE;

    sched_cleanup(gba);

    sched_init(gba);
    mem_reset(&gba->memory);
    io_init(&gba->io);
    ppu_init(gba);
    apu_init(gba);
    core_init(gba);
    gpio_init(gba);

#ifdef WITH_DEBUGGER
    debugger_init(&gba->debugger);
#endif
}

/*
** Skip the BIOS, setting all the registers to their final state.
**
** This is meant to be called right after `gba_reset()`.
*/
static
void
gba_skip_bios(
    struct gba *gba
) {
    core_switch_mode(&gba->core, MODE_SYS);
    gba->core.cpsr.raw &= 0x1F;
    gba->core.r13_svc = 0x03007FE0;
    gba->core.r13_irq = 0x03007FA0;
    gba->core.sp = 0X03007F00;
    gba->core.pc = 0x08000000;
    gba->io.postflg = 1;
    core_reload_pipeline(gba);
}

/*
** Run the emulator, consuming messages that dictate what the emulator should do.
**
** Messages are used as a mono-directional communication between the frontend and the emulator.
**
** Those messages can be:
**   - A new key was pressed
**   - The user requested a quickload/quicksave
**   - The emulator must run until the next frame, for one instruction, etc.
**   - The emulator must pause, reset, etc.
*/
void
gba_main_loop(
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

        pthread_mutex_lock(&gba->message_queue.lock);

        mqueue = &gba->message_queue;
        message = mqueue->messages;
        while (mqueue->length) {
            switch (message->type) {
                case MESSAGE_EXIT: {
                    pthread_mutex_unlock(&gba->message_queue.lock);
                    return ;
                };
                case MESSAGE_BIOS: {
                    struct message_data *message_data;

                    message_data = (struct message_data *)message;
                    memset(gba->memory.bios, 0, BIOS_MASK);
                    memcpy(gba->memory.bios, message_data->data, min(message_data->size, BIOS_MASK));
                    if (message_data->cleanup) {
                        message_data->cleanup(message_data->data);
                    }
                    break;
                };
                case MESSAGE_ROM: {
                    struct message_data *message_data;

                    message_data = (struct message_data *)message;
                    memset(gba->memory.rom, 0, CART_SIZE);
                    gba->memory.rom_size = min(message_data->size, CART_SIZE);
                    memcpy(gba->memory.rom, message_data->data, gba->memory.rom_size);
                    if (message_data->cleanup) {
                        message_data->cleanup(message_data->data);
                    }
                    db_lookup_game(gba);
                    break;
                };
                case MESSAGE_BACKUP: {
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

                    /* Ignore if emulation is already started. */
                    if (gba->started) {
                        break;
                    }

                    message_backup_type = (struct message_backup_type *)message;
                    if (message_backup_type->type == BACKUP_AUTO_DETECT) {
                        mem_backup_storage_detect(gba);
                    } else {
                        gba->memory.backup_storage_type = message_backup_type->type;
                        gba->memory.backup_storage_source = BACKUP_SOURCE_MANUAL;
                    }
                    mem_backup_storage_init(gba);
                    break;
                };
                case MESSAGE_RESET: {
                    struct message_reset *message_reset;

                    message_reset = (struct message_reset *)message;

                    gba_reset(gba);
                    last_measured_time = hs_tick_count();
                    accumulated_time = 0;

                    if (message_reset->skip_bios) {
                        gba_skip_bios(gba);
                    }
                    break;
                };
                case MESSAGE_SPEED: {
                    struct message_speed *message_run;

                    message_run = (struct message_speed *)message;
                    gba->speed = message_run->speed;
                    if (message_run->speed) {
                        time_per_frame = 1.f / 59.737f * 1000.f * 1000.f / (float)gba->speed;
                        accumulated_time = 0;
                    } else {
                        time_per_frame = 0.f;
                    }
                    break;
                };
                case MESSAGE_RUN: {
                    gba->started = true;
                    gba->state = GBA_STATE_RUN;
                    break;
                };
                case MESSAGE_PAUSE: {
                    gba->state = GBA_STATE_PAUSE;
#ifdef WITH_DEBUGGER
                    gba->debugger.interrupt.reason = GBA_INTERRUPT_REASON_PAUSE;
                    gba->debugger.interrupt.flag = true;
#endif
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

                    io_scan_keypad_irq(gba);
                    break;
                };
                case MESSAGE_QUICKLOAD: {
                    struct message_data *message_data;

                    message_data = (struct message_data *)message;
                    quickload(gba, (char const *)message_data->data);
                    if (message_data->cleanup) {
                        message_data->cleanup(message_data->data);
                    }
                    break;
                };
                case MESSAGE_QUICKSAVE: {
                    struct message_data *message_data;

                    message_data = (struct message_data *)message;
                    quicksave(gba, (char const *)message_data->data);
                    if (message_data->cleanup) {
                        message_data->cleanup(message_data->data);
                    }
                    break;
                };
                case MESSAGE_AUDIO_RESAMPLE_FREQ: {
                    struct message_audio_freq *message_audio_freq;

                    message_audio_freq = (struct message_audio_freq *)message;
                    gba->apu.resample_frequency = message_audio_freq->resample_frequency;
                    break;
                };
                case MESSAGE_SETTINGS_COLOR_CORRECTION: {
                    struct message_color_correction *message_color_correction;

                    message_color_correction = (struct message_color_correction *)message;
                    gba->color_correction = message_color_correction->color_correction;
                    break;
                };
                case MESSAGE_SETTINGS_RTC: {
                    struct message_device_state *message_device_state;

                    /* Ignore if emulation is already started. */
                    if (gba->started) {
                        break;
                    }

                    message_device_state = (struct message_device_state *)message;
                    switch (message_device_state->state) {
                        case DEVICE_AUTO_DETECT: {
                            gba->rtc_auto_detect = true;
                            gba->rtc_enabled = false;
                            break;
                        };
                        case DEVICE_ENABLED: {
                            gba->rtc_auto_detect = false;
                            gba->rtc_enabled = true;
                            break;
                        };
                        case DEVICE_DISABLED: {
                            gba->rtc_auto_detect = false;
                            gba->rtc_enabled = false;
                            break;
                        };
                    }
                    break;
                };
#ifdef WITH_DEBUGGER
                case MESSAGE_DBG_FRAME: {
                    gba->started = true;
                    gba->state = GBA_STATE_FRAME;
                    break;
                };
                case MESSAGE_DBG_TRACE: {
                    struct message_dbg_trace *message_dbg_trace;

                    message_dbg_trace = (struct message_dbg_trace *)message;
                    gba->debugger.trace.count = message_dbg_trace->count;
                    gba->debugger.trace.data = message_dbg_trace->data;
                    gba->debugger.trace.tracer = message_dbg_trace->tracer;

                    gba->started = true;
                    gba->state = GBA_STATE_TRACE;
                    break;
                };
                case MESSAGE_DBG_STEP: {
                    struct message_dbg_step *message_dbg_step;

                    message_dbg_step = (struct message_dbg_step *)message;

                    gba->started = true;
                    gba->state = message_dbg_step->over ? GBA_STATE_STEP_OVER : GBA_STATE_STEP_IN;
                    gba->debugger.step.count = message_dbg_step->count;
                    gba->debugger.step.next_pc = gba->core.pc + (gba->core.cpsr.thumb ? 2 : 4);
                    break;
                };
                case MESSAGE_DBG_BREAKPOINTS: {
                    struct message_dbg_breakpoints *message_dbg_breakpoints;

                    message_dbg_breakpoints = (struct message_dbg_breakpoints *)message;
                    if (gba->debugger.breakpoints.cleanup) {
                        gba->debugger.breakpoints.cleanup(gba->debugger.breakpoints.list);
                    }
                    gba->debugger.breakpoints.list = message_dbg_breakpoints->breakpoints;
                    gba->debugger.breakpoints.len = message_dbg_breakpoints->len;
                    gba->debugger.breakpoints.cleanup = message_dbg_breakpoints->cleanup;
                    break;
                };
                case MESSAGE_DBG_WATCHPOINTS: {
                    struct message_dbg_watchpoints *message_dbg_watchpoints;

                    message_dbg_watchpoints = (struct message_dbg_watchpoints *)message;
                    if (gba->debugger.watchpoints.cleanup) {
                        gba->debugger.watchpoints.cleanup(gba->debugger.watchpoints.list);
                    }
                    gba->debugger.watchpoints.list = message_dbg_watchpoints->watchpoints;
                    gba->debugger.watchpoints.len = message_dbg_watchpoints->len;
                    gba->debugger.watchpoints.cleanup = message_dbg_watchpoints->cleanup;
                    break;
                };
#endif
                default: unimplemented(HS_CORE, "GBA message type with ID %i unimplemented.", message->type);
            }
            mqueue->allocated_size -= message->size;
            --mqueue->length;
            message = (struct message *)((uint8_t *)message + message->size);
        }
        free(mqueue->messages);
        mqueue->messages = NULL;

        pthread_mutex_unlock(&gba->message_queue.lock);

        switch (gba->state) {
            case GBA_STATE_PAUSE: {
                // Wait until there's new messages in the message queue.
                pthread_mutex_lock(&gba->message_queue.lock);
                pthread_cond_wait(&gba->message_queue.ready, &gba->message_queue.lock);
                pthread_mutex_unlock(&gba->message_queue.lock);
            };
            case GBA_STATE_RUN: {
                sched_run_for(gba, CYCLES_PER_FRAME);
                break;
            };
#ifdef WITH_DEBUGGER
            case GBA_STATE_FRAME: {
                sched_run_for(gba, CYCLES_PER_FRAME - (gba->core.cycles % CYCLES_PER_FRAME));
                gba->state = GBA_STATE_PAUSE;
                gba->debugger.interrupt.reason = GBA_INTERRUPT_REASON_FRAME_FINISHED;
                gba->debugger.interrupt.flag = true;
                break;
            };
            case GBA_STATE_TRACE: {
                size_t cnt;

                cnt = 1000; // Split the process in chunks of 1000 insns.

                while (cnt && gba->debugger.trace.count) {
                    sched_run_for(gba, 1);
                    gba->debugger.trace.tracer(gba->debugger.trace.data);

                    --gba->debugger.trace.count;
                    --cnt;
                }

                if (!gba->debugger.trace.count) {
                    gba->state = GBA_STATE_PAUSE;
                    gba->debugger.interrupt.reason = GBA_INTERRUPT_REASON_TRACE_FINISHED;
                    gba->debugger.interrupt.flag = true;
                }
                break;
            };
            case GBA_STATE_STEP_IN: {
                size_t cnt;

                cnt = 1000; // Split the process in chunks of 1000 insns.

                while (cnt && gba->debugger.step.count) {
                    sched_run_for(gba, 1);
                    --gba->debugger.step.count;
                    --cnt;
                }

                if (!gba->debugger.step.count) {
                    gba->state = GBA_STATE_PAUSE;
                    gba->debugger.interrupt.reason = GBA_INTERRUPT_REASON_STEP_FINISHED;
                    gba->debugger.interrupt.flag = true;
                }
                break;
            };
            case GBA_STATE_STEP_OVER: {
                size_t cnt;

                cnt = 1000; // Split the process in chunks of 1000 insns.

                while (cnt && gba->debugger.step.count) {
                    while (cnt && gba->core.pc != gba->debugger.step.next_pc) {
                        sched_run_for(gba, 1);
                        --cnt;
                    }

                    if (gba->core.pc == gba->debugger.step.next_pc) {
                        --gba->debugger.step.count;
                        gba->debugger.step.next_pc += (gba->core.cpsr.thumb ? 2 : 4);
                    }
                }

                if (!gba->debugger.step.count) {
                    gba->state = GBA_STATE_PAUSE;
                    gba->debugger.interrupt.reason = GBA_INTERRUPT_REASON_STEP_FINISHED;
                    gba->debugger.interrupt.flag = true;
                }
                break;
            };
#endif
            default: unimplemented(HS_DEBUG, "Unimplemented GBA run operation %i.", gba->state);
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
            accumulated_time -= time_per_frame;
        } else {
            last_measured_time = hs_tick_count();
            accumulated_time = 0;
        }
    }
}

/*
** Put the given message in the message queue.
*/
static
void
gba_message_push(
    struct gba *gba,
    struct message *message
) {
    size_t new_size;
    struct message_queue *mqueue;

    mqueue = &gba->message_queue;
    pthread_mutex_lock(&gba->message_queue.lock);

    new_size = mqueue->allocated_size + message->size;

    mqueue->messages = realloc(mqueue->messages, new_size);
    hs_assert(mqueue->messages);
    memcpy((uint8_t *)mqueue->messages + mqueue->allocated_size, message, message->size);

    mqueue->length += 1;
    mqueue->allocated_size = new_size;

    pthread_cond_broadcast(&gba->message_queue.ready);
    pthread_mutex_unlock(&gba->message_queue.lock);
}

void
gba_send_exit(
    struct gba *gba
) {
    gba_message_push(
        gba,
        &((struct message) {
            .type = MESSAGE_EXIT,
            .size = sizeof(struct message),
        })
    );
}

void
gba_send_bios(
    struct gba *gba,
    uint8_t *data,
    void (*cleanup)(void *)
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_data) {
            .super = (struct message){
                .size = sizeof(struct message_data),
                .type = MESSAGE_BIOS,
            },
            .data = data,
            .size = BIOS_SIZE,
            .cleanup = cleanup,
        })
    );
}

void
gba_send_rom(
    struct gba *gba,
    uint8_t *data,
    size_t size,
    void (*cleanup)(void *)
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_data) {
            .super = (struct message){
                .type = MESSAGE_ROM,
                .size = sizeof(struct message_data),
            },
            .data = data,
            .size = size,
            .cleanup = cleanup,
        })
    );
}

void
gba_send_backup(
    struct gba *gba,
    uint8_t *data,
    size_t size,
    void (*cleanup)(void *)
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_data) {
            .super = (struct message){
                .type = MESSAGE_BACKUP,
                .size = sizeof(struct message_data),
            },
            .data = data,
            .size = size,
            .cleanup = cleanup,
        })
    );
}

void
gba_send_backup_type(
    struct gba *gba,
    enum backup_storage_types backup_type
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_backup_type) {
            .super = (struct message){
                .type = MESSAGE_BACKUP_TYPE,
                .size = sizeof(struct message_backup_type),
            },
            .type = backup_type,
        })
    );
}

void
gba_send_speed(
    struct gba *gba,
    uint32_t speed
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_speed) {
            .super = (struct message){
                .type = MESSAGE_SPEED,
                .size = sizeof(struct message_speed),
            },
            .speed = speed,
        })
    );
}

void
gba_send_reset(
    struct gba *gba,
    bool skip_bios
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_reset) {
            .super = (struct message){
                .type = MESSAGE_RESET,
                .size = sizeof(struct message_reset),
            },
            .skip_bios = skip_bios,
        })
    );
}

void
gba_send_run(
    struct gba *gba
) {
    gba_message_push(
        gba,
        &((struct message) {
            .type = MESSAGE_RUN,
            .size = sizeof(struct message),
        })
    );
}

void
gba_send_pause(
    struct gba *gba
) {
    gba_message_push(
        gba,
        &((struct message) {
            .type = MESSAGE_PAUSE,
            .size = sizeof(struct message),
        })
    );
}

void
gba_send_keyinput(
    struct gba *gba,
    enum keyinput key,
    bool pressed
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_keyinput) {
            .super = (struct message){
                .type = MESSAGE_KEYINPUT,
                .size = sizeof(struct message_keyinput),
            },
            .key = key,
            .pressed = pressed,
        })
    );
}

void
gba_send_quickload(
    struct gba *gba,
    char const *path
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_data) {
            .super = (struct message){
                .type = MESSAGE_QUICKLOAD,
                .size = sizeof(struct message_data),
            },
            .data = (unsigned char *)strdup(path),
            .size = strlen(path),
            .cleanup = free,
        })
    );
}

void
gba_send_quicksave(
    struct gba *gba,
    char const *path
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_data) {
            .super = (struct message){
                .type = MESSAGE_QUICKSAVE,
                .size = sizeof(struct message_data),
            },
            .data = (unsigned char *)strdup(path),
            .size = strlen(path),
            .cleanup = free,
        })
    );
}

void
gba_send_audio_resample_freq(
    struct gba *gba,
    uint64_t resample_freq
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_audio_freq) {
            .super = (struct message){
                .type = MESSAGE_AUDIO_RESAMPLE_FREQ,
                .size = sizeof(struct message_audio_freq),
            },
            .resample_frequency = resample_freq,
        })
    );
}

void
gba_send_settings_color_correction(
    struct gba *gba,
    bool color_correction
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_color_correction) {
            .super = (struct message){
                .type = MESSAGE_SETTINGS_COLOR_CORRECTION,
                .size = sizeof(struct message_color_correction),
            },
            .color_correction = color_correction,
        })
    );
}

void
gba_send_settings_rtc(
    struct gba *gba,
    enum device_states state
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_device_state) {
            .super = (struct message){
                .type = MESSAGE_SETTINGS_RTC,
                .size = sizeof(struct message_device_state),
            },
            .state = state,
        })
    );
}

#ifdef WITH_DEBUGGER

void
gba_send_dbg_frame(
    struct gba *gba
) {
    gba_message_push(
        gba,
        &((struct message) {
            .type = MESSAGE_DBG_FRAME,
            .size = sizeof(struct message),
        })
    );
}

void
gba_send_dbg_trace(
    struct gba *gba,
    size_t count,
    void *data,
    void (*tracer)(void *gba)
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_dbg_trace) {
            .super = (struct message){
                .type = MESSAGE_DBG_TRACE,
                .size = sizeof(struct message_dbg_trace),
            },
            .count = count,
            .data = data,
            .tracer = tracer,
        })
    );
}

void
gba_send_dbg_step(
    struct gba *gba,
    bool over,
    size_t count
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_dbg_step) {
            .super = (struct message){
                .type = MESSAGE_DBG_STEP,
                .size = sizeof(struct message_dbg_step),
            },
            .over = over,
            .count = count,
        })
    );
}

void
gba_send_dbg_breakpoints(
    struct gba *gba,
    struct breakpoint *breakpoints,
    size_t len,
    void (*cleanup)(void *)
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_dbg_breakpoints) {
            .super = (struct message){
                .type = MESSAGE_DBG_BREAKPOINTS,
                .size = sizeof(struct message_dbg_breakpoints),
            },
            .breakpoints = breakpoints,
            .len = len,
            .cleanup = cleanup,
        })
    );
}

void
gba_send_dbg_watchpoints(
    struct gba *gba,
    struct watchpoint *watchpoints,
    size_t len,
    void (*cleanup)(void *)
) {
    gba_message_push(
        gba,
        (struct message *)&((struct message_dbg_watchpoints) {
            .super = (struct message){
                .type = MESSAGE_DBG_WATCHPOINTS,
                .size = sizeof(struct message_dbg_watchpoints),
            },
            .watchpoints = watchpoints,
            .len = len,
            .cleanup = cleanup,
        })
    );
}

#endif