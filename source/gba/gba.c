/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "gba/gba.h"
#include "gba/core/arm.h"
#include "gba/core/thumb.h"
#include "gba/channel.h"
#include "gba/event.h"

/*
** Create a new GBA emulator.
*/
struct gba *
gba_create(void)
{
    struct gba *gba;

    gba = malloc(sizeof(struct gba));
    hs_assert(gba);

    memset(gba, 0, sizeof(*gba));

    // Initialize the ARM and Thumb decoder
    {
        core_arm_decode_insns();
        core_thumb_decode_insns();
    }

    // Channels
    {
        channel_init(&gba->channels.messages);
        channel_init(&gba->channels.notifications);
#ifdef WITH_DEBUGGER
        channel_init(&gba->channels.debug);
#endif
    }

    // Shared Data
    {
        pthread_mutex_init(&gba->shared_data.framebuffer.lock, NULL);
        pthread_mutex_init(&gba->shared_data.audio_rbuffer_mutex, NULL);
    }

    return (gba);
}

void
gba_send_notification_raw(
    struct gba *gba,
    struct event_header const *notif_header
) {
    switch (notif_header->kind) {
        case NOTIFICATION_RESET:
        case NOTIFICATION_PAUSE:
        case NOTIFICATION_STOP:
        case NOTIFICATION_RUN: {
            channel_lock(&gba->channels.notifications);
            channel_push(&gba->channels.notifications, notif_header);
            channel_release(&gba->channels.notifications);

#ifdef WITH_DEBUGGER
            channel_lock(&gba->channels.debug);
            channel_push(&gba->channels.debug, notif_header);
            channel_release(&gba->channels.debug);
#endif

            break;
        };
        case NOTIFICATION_QUICKSAVE:
        case NOTIFICATION_QUICKLOAD: {
            channel_lock(&gba->channels.notifications);
            channel_push(&gba->channels.notifications, notif_header);
            channel_release(&gba->channels.notifications);
            break;
        };
#ifdef WITH_DEBUGGER
        case NOTIFICATION_BREAKPOINTS_LIST_SET:
        case NOTIFICATION_WATCHPOINTS_LIST_SET:
        case NOTIFICATION_WATCHPOINT:
        case NOTIFICATION_BREAKPOINT: {
            channel_lock(&gba->channels.debug);
            channel_push(&gba->channels.debug, notif_header);
            channel_release(&gba->channels.debug);
            break;
        }
#endif
        default: {
            unimplemented(HS_ERROR, "Unimplemented notification kind %i.", notif_header->kind);
            break;
        }
    }
}

void
gba_send_notification(
    struct gba *gba,
    enum notification_kind kind
) {
    struct notification notif;

    notif.header.kind = kind;
    notif.header.size = sizeof(notif);
    gba_send_notification_raw(gba, &notif.header);
}

static void
gba_state_stop(
    struct gba *gba
) {
    free(gba->scheduler.events);
    gba->scheduler.events = NULL;

    free(gba->shared_data.backup_storage.data);
    gba->shared_data.backup_storage.data = NULL;

    gba->state = GBA_STATE_STOP;
    gba_send_notification(gba, NOTIFICATION_STOP);
}

void
gba_state_pause(
    struct gba *gba
) {
    gba->state = GBA_STATE_PAUSE;
    gba_send_notification(gba, NOTIFICATION_PAUSE);
}

void
gba_state_run(
    struct gba *gba
) {
    gba->state = GBA_STATE_RUN;
    sched_reset_frame_limiter(gba);
    gba_send_notification(gba, NOTIFICATION_RUN);
}

static void
gba_state_reset(
    struct gba *gba,
    struct launch_config const *config
) {
    // Scheduler
    {
        struct scheduler *scheduler;

        scheduler = &gba->scheduler;
        memset(scheduler, 0, sizeof(*scheduler));

        scheduler->events_size = 64;
        scheduler->events = calloc(scheduler->events_size, sizeof(struct scheduler_event));
        hs_assert(scheduler->events);

        sched_update_speed(gba, config->speed);

        // Frame limiter
        sched_add_event(
            gba,
            NEW_REPEAT_EVENT(
                SCHED_EVENT_FRAME_LIMITER,
                GBA_CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH * GBA_SCREEN_REAL_HEIGHT,  // Timing of first trigger
                GBA_CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH * GBA_SCREEN_REAL_HEIGHT   // Period
            )
        );
    }

    // Memory
    {
        struct memory *memory;

        memory = &gba->memory;
        memset(memory, 0, sizeof(*memory));

        // Copy the BIOS and ROM to memory
        memcpy(gba->memory.bios, config->bios.data, min(config->bios.size, BIOS_SIZE));
        memcpy(gba->memory.rom, config->rom.data, min(config->rom.size, CART_SIZE));
        gba->memory.rom_size = config->rom.size;
    }

    // IO
    {
        struct io *io;

        io = &gba->io;
        memset(io, 0, sizeof(*io));

        io->keyinput.raw = 0x3FF; // Every button set to "released"
        io->soundbias.bias = 0x200;
        io->bg_pa[0].raw = 0x100;
        io->bg_pd[0].raw = 0x100;
        io->bg_pa[1].raw = 0x100;
        io->bg_pd[1].raw = 0x100;
        io->timers[0].handler = INVALID_EVENT_HANDLE;
        io->timers[1].handler = INVALID_EVENT_HANDLE;
        io->timers[2].handler = INVALID_EVENT_HANDLE;
        io->timers[3].handler = INVALID_EVENT_HANDLE;
        io->dma[0].enable_event_handle = INVALID_EVENT_HANDLE;
        io->dma[1].enable_event_handle = INVALID_EVENT_HANDLE;
        io->dma[2].enable_event_handle = INVALID_EVENT_HANDLE;
        io->dma[3].enable_event_handle = INVALID_EVENT_HANDLE;
        io->dma[0].index = 0;
        io->dma[1].index = 1;
        io->dma[2].index = 2;
        io->dma[3].index = 3;
    }

    // APU
    {
        struct apu *apu;

        apu = &gba->apu;
        memset(apu, 0, sizeof(*apu));

        gba->apu.tone_and_sweep.step_handler = INVALID_EVENT_HANDLE;
        gba->apu.tone.step_handler = INVALID_EVENT_HANDLE;
        gba->apu.wave.step_handler = INVALID_EVENT_HANDLE;
        gba->apu.noise.step_handler = INVALID_EVENT_HANDLE;

        sched_add_event(
            gba,
            NEW_REPEAT_EVENT(
                SCHED_EVENT_APU_MODULES_STEP,
                0,
                GBA_CYCLES_PER_SECOND / 512
            )
        );

        if (config->audio_frequency) {
            sched_add_event(
                gba,
                NEW_REPEAT_EVENT(
                    SCHED_EVENT_APU_RESAMPLE,
                    0,
                    config->audio_frequency
                )
            );
        }
    }

    // PPU
    {
        struct ppu *ppu;

        ppu = &gba->ppu;
        memset(ppu, 0, sizeof(*ppu));

        // HDraw
        sched_add_event(
            gba,
            NEW_REPEAT_EVENT(
                SCHED_EVENT_PPU_HDRAW,
                GBA_CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH,       // Timing of first trigger
                GBA_CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH        // Period
            )
        );

        // HBlank
        sched_add_event(
            gba,
            NEW_REPEAT_EVENT(
                SCHED_EVENT_PPU_HBLANK,
                GBA_CYCLES_PER_PIXEL * GBA_SCREEN_WIDTH + 46,       // Timing of first trigger
                GBA_CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH        // Period
            )
        );
    }

    // GPIO
    {
        struct gpio *gpio;

        gpio = &gba->gpio;
        memset(gpio, 0, sizeof(*gpio));

        gpio->device = config->gpio_device_type;
        switch (config->gpio_device_type) {
            case GPIO_RTC: {
                gpio->rtc.enabled = true;
                gpio->rtc.state = RTC_COMMAND;
                gpio->rtc.data_len = 8;
                break;
            };
            default: break;
        }
    }

    // Backup storage
    {
        gba->memory.backup_storage.type = config->backup_storage.type;
        switch (gba->memory.backup_storage.type) {
            case BACKUP_EEPROM_4K: {
                gba->memory.backup_storage.chip.eeprom.mask = (gba->memory.rom_size > 16 * 1024 * 1024) ? 0x01FFFF00 : 0xFF000000;
                gba->memory.backup_storage.chip.eeprom.range = (gba->memory.rom_size > 16 * 1024 * 1024) ? 0x01FFFF00 : 0x0d000000;
                gba->memory.backup_storage.chip.eeprom.address_mask = EEPROM_4K_ADDR_MASK;
                gba->memory.backup_storage.chip.eeprom.address_len = EEPROM_4K_ADDR_LEN;
                gba->shared_data.backup_storage.size = EEPROM_4K_SIZE;
                break;
            };
            case BACKUP_EEPROM_64K: {
                gba->memory.backup_storage.chip.eeprom.mask = (gba->memory.rom_size > 16 * 1024 * 1024) ? 0x01FFFF00 : 0xFF000000;
                gba->memory.backup_storage.chip.eeprom.range = (gba->memory.rom_size > 16 * 1024 * 1024) ? 0x01FFFF00 : 0x0d000000;
                gba->memory.backup_storage.chip.eeprom.address_mask = EEPROM_64K_ADDR_MASK;
                gba->memory.backup_storage.chip.eeprom.address_len = EEPROM_64K_ADDR_LEN;
                gba->shared_data.backup_storage.size = EEPROM_64K_SIZE;
                break;
            };
            case BACKUP_SRAM: gba->shared_data.backup_storage.size = SRAM_SIZE; break;
            case BACKUP_FLASH64: gba->shared_data.backup_storage.size = FLASH64_SIZE; break;
            case BACKUP_FLASH128:gba->shared_data.backup_storage.size = FLASH128_SIZE; break;
            case BACKUP_NONE: gba->shared_data.backup_storage.size = 0; break;
            default: panic(HS_CORE, "Unknown backup type %i", gba->memory.backup_storage.type); break;
        }

        if (gba->shared_data.backup_storage.size) {
            gba->shared_data.backup_storage.data = malloc(gba->shared_data.backup_storage.size);
            hs_assert(gba->shared_data.backup_storage.data);

            memset(gba->shared_data.backup_storage.data, 0xFF, gba->shared_data.backup_storage.size);

            if (config->backup_storage.data && config->backup_storage.size) {
                memcpy(gba->shared_data.backup_storage.data, config->backup_storage.data, min(gba->shared_data.backup_storage.size, config->backup_storage.size));
            }
        }
    }

    // Core
    {
        struct core *core;

        core = &gba->core;

        memset(core, 0, sizeof(*core));

        mem_update_waitstates(gba);

        core->cpsr.mode = MODE_SYS;
        core->prefetch[0] = 0xF0000000;
        core->prefetch[1] = 0xF0000000;
        core->prefetch_access_type = NON_SEQUENTIAL;

        if (config->skip_bios) {
            core->r13_irq = 0x03007FA0;
            core->r13_svc = 0x03007FE0;
            core->sp = 0x03007F00;
            core->pc = 0x08000000;
            gba->io.postflg = 1;
            gba->io.rcnt.raw = 0x8000;
            gba->memory.bios_bus = 0xe129f000;
            core_reload_pipeline(gba);
        } else {
            core_interrupt(gba, VEC_RESET, MODE_SVC, false);
        }
    }

    gba_send_notification(gba, NOTIFICATION_RESET);
}

static
void
gba_process_message(
    struct gba *gba,
    struct message const *message
) {
    switch (message->header.kind) {
        case MESSAGE_EXIT: {
            gba->exit = true;
            break;
        };
        case MESSAGE_RESET: {
            struct message_reset const *msg_reset;

            msg_reset = (struct message_reset const *)message;

            gba_state_stop(gba);
            gba_state_reset(gba, &msg_reset->config);
            break;
        };
        case MESSAGE_RUN: {
#ifdef WITH_DEBUGGER
            gba->debugger.run_mode = GBA_RUN_MODE_NORMAL;
#endif
            gba_state_run(gba);
            break;
        };
        case MESSAGE_STOP: {
            gba_state_stop(gba);
            break;
        };
        case MESSAGE_PAUSE: {
            gba_state_pause(gba);
            break;
        };
        case MESSAGE_KEY: {
            struct message_key const *msg_key;

            msg_key = (struct message_key const *)message;
            switch (msg_key->key) {
                case KEY_A:         gba->io.keyinput.a = !msg_key->pressed; break;
                case KEY_B:         gba->io.keyinput.b = !msg_key->pressed; break;
                case KEY_L:         gba->io.keyinput.l = !msg_key->pressed; break;
                case KEY_R:         gba->io.keyinput.r = !msg_key->pressed; break;
                case KEY_UP:        gba->io.keyinput.up = !msg_key->pressed; break;
                case KEY_DOWN:      gba->io.keyinput.down = !msg_key->pressed; break;
                case KEY_RIGHT:     gba->io.keyinput.right = !msg_key->pressed; break;
                case KEY_LEFT:      gba->io.keyinput.left = !msg_key->pressed; break;
                case KEY_START:     gba->io.keyinput.start = !msg_key->pressed; break;
                case KEY_SELECT:    gba->io.keyinput.select = !msg_key->pressed; break;
                default:            break;
            };

            if (gba->core.state == CORE_STOP && io_evaluate_keypad_cond(gba)) {
                gba->core.state = CORE_RUN;
                sched_reset_frame_limiter(gba);
            }

            io_scan_keypad_irq(gba);
            break;
        };
        case MESSAGE_SPEED: {
            struct message_speed const *msg_speed;

            msg_speed = (struct message_speed const *)message;
            sched_update_speed(gba, msg_speed->speed);
            break;
        };
        case MESSAGE_QUICKSAVE: {
            struct notification_quicksave notif;

            notif.header.kind = NOTIFICATION_QUICKSAVE;
            notif.header.size = sizeof(struct notification_quicksave);
            quicksave(gba, &notif.data, &notif.size);
            gba_send_notification_raw(gba, &notif.header);
            break;
        };
        case MESSAGE_QUICKLOAD: {
            struct message_quickload const *msg_quickload;

            msg_quickload = (struct message_quickload const *)message;
            quickload(gba, msg_quickload->data, msg_quickload->size); // TODO FIXME Send back & handle any errors when loading the save state.
            gba_send_notification(gba, NOTIFICATION_QUICKLOAD);
            break;
        };
#ifdef WITH_DEBUGGER
        case MESSAGE_FRAME: {
            struct message_frame const *msg_frame;

            msg_frame = (struct message_frame const *)message;

            gba->debugger.frame.count = msg_frame->count;
            gba->debugger.run_mode = GBA_RUN_MODE_FRAME;

            gba_state_run(gba);
            break;
        };
        case MESSAGE_TRACE: {
            struct message_trace const *msg_trace;

            msg_trace = (struct message_trace const *)message;

            gba->debugger.trace.count = msg_trace->count;
            gba->debugger.trace.tracer_cb = msg_trace->tracer_cb;
            gba->debugger.trace.arg = msg_trace->arg;

            gba->debugger.run_mode = GBA_RUN_MODE_TRACE;
            gba_state_run(gba);
            break;
        };
        case MESSAGE_STEP_IN:
        case MESSAGE_STEP_OVER: {
            struct message_step const *msg_step;

            msg_step = (struct message_step const *)message;

            gba->debugger.step.count = msg_step->count;
            gba->debugger.step.next_pc = gba->core.pc + (gba->core.cpsr.thumb ? 2 : 4);

            gba->debugger.run_mode = message->header.kind == MESSAGE_STEP_OVER ? GBA_RUN_MODE_STEP_OVER : GBA_RUN_MODE_STEP_IN;
            gba_state_run(gba);
            break;
        };
        case MESSAGE_SET_BREAKPOINTS_LIST: {
            struct message_set_breakpoints_list const *msg_set_breakpoints_list;

            msg_set_breakpoints_list = (struct message_set_breakpoints_list const *)message;

            free(gba->debugger.breakpoints.list);
            gba->debugger.breakpoints.len = msg_set_breakpoints_list->len;
            gba->debugger.breakpoints.list = calloc(gba->debugger.breakpoints.len, sizeof(struct breakpoint));
            hs_assert(gba->debugger.breakpoints.list);
            memcpy(gba->debugger.breakpoints.list, msg_set_breakpoints_list->breakpoints, sizeof(struct breakpoint) * gba->debugger.breakpoints.len);

            gba_send_notification(gba, NOTIFICATION_BREAKPOINTS_LIST_SET);
            break;
        };
        case MESSAGE_SET_WATCHPOINTS_LIST: {
            struct message_set_watchpoints_list const *msg_set_watchpoints_list;

            msg_set_watchpoints_list = (struct message_set_watchpoints_list const *)message;

            free(gba->debugger.watchpoints.list);
            gba->debugger.watchpoints.len = msg_set_watchpoints_list->len;
            gba->debugger.watchpoints.list = calloc(gba->debugger.watchpoints.len, sizeof(struct watchpoint));
            hs_assert(gba->debugger.watchpoints.list);
            memcpy(gba->debugger.watchpoints.list, msg_set_watchpoints_list->watchpoints, sizeof(struct watchpoint) * gba->debugger.watchpoints.len);

            gba_send_notification(gba, NOTIFICATION_WATCHPOINTS_LIST_SET);
            break;
        };
#endif
    }
}

/*
** Run the given GBA emulator.
** This will process all the message sent to the gba until an exit message is sent.
*/
void
gba_run(
    struct gba *gba
) {
    struct channel *messages;

    messages = &gba->channels.messages;

    while (!gba->exit) {
        // Consume all messages
        {
            struct message const *msg;

            channel_lock(messages);

            msg = (struct message const *)channel_next(messages, NULL);
            while (msg) {
                gba_process_message(gba, msg);
                msg = (struct message const *)channel_next(messages, &msg->header);
            }

            channel_clear(messages);

            // If the exit flag was raised, leave now
            if (gba->exit) {
                return ;
            }

            // Wait until there's new messages in the message queue.
            if (gba->state == GBA_STATE_PAUSE) {
                channel_wait(messages);
            }

            channel_release(messages);
        }

        // Process the current state
        switch (gba->state) {
            case GBA_STATE_STOP:
            case GBA_STATE_PAUSE: {
                break;
            }
            case GBA_STATE_RUN: {
#ifdef WITH_DEBUGGER
                debugger_execute_run_mode(gba);
#else
                sched_run_for(gba, GBA_CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH);
#endif
                break;
            };
        }
    }
}

/*
** Delete the given GBA and all its resources.
*/
void
gba_delete(
    struct gba *gba
) {
    free(gba);
}

/*
** Lock the mutex protecting the framebuffer shared with the frontend.
*/
void
gba_shared_framebuffer_lock(
    struct gba *gba
) {
    pthread_mutex_lock(&gba->shared_data.framebuffer.lock);
}

/*
** Release the mutex protecting the framebuffer shared with the frontend.
*/
void
gba_shared_framebuffer_release(
    struct gba *gba
) {
    pthread_mutex_unlock(&gba->shared_data.framebuffer.lock);
}

/*
** Lock the mutex protecting the audio ring buffer shared with the frontend.
*/
void
gba_shared_audio_rbuffer_lock(
    struct gba *gba
) {
    pthread_mutex_lock(&gba->shared_data.audio_rbuffer_mutex);
}

/*
** Release the mutex protecting the audio ring buffer shared with the frontend.
*/
void
gba_shared_audio_rbuffer_release(
    struct gba *gba
) {
    pthread_mutex_unlock(&gba->shared_data.audio_rbuffer_mutex);
}

/*
** Release the mutex protecting the audio ring buffer shared with the frontend.
*/
uint32_t
gba_shared_audio_rbuffer_pop_sample(
    struct gba *gba
) {
    return (apu_rbuffer_pop(&gba->shared_data.audio_rbuffer));
}

/*
** Reset the frame counter and return its old value.
*/
uint32_t
gba_shared_reset_frame_counter(
    struct gba *gba
) {
    return (atomic_exchange(&gba->shared_data.frame_counter, 0));
}

/*
** Delete a notification.
** Must be called by the frontend/debugger for each received notifications.
*/
void
gba_delete_notification(
    struct notification const *notif
) {
    switch (notif->header.kind) {
        case NOTIFICATION_QUICKSAVE: {
            struct notification_quicksave *qsave;

            qsave = (struct notification_quicksave *)notif;
            free(qsave->data);
            break;
        }
    }
}
