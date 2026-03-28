/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"

// Not always true, but it's for optimization purposes so it's not a big deal
// if the page size isn't 4k.
#define PAGE_SIZE           4096u
#define PAGE_MASK           (PAGE_SIZE - 1)
#define PAGE_ALIGN(size)    ((size + PAGE_SIZE) & ~PAGE_MASK)

struct quicksave_buffer {
    uint8_t *data;
    size_t size;    // Allocated size
    size_t index;   // Read/Write index
};

static
void
quicksave_write(
    struct quicksave_buffer *buffer,
    uint8_t const *data,
    size_t length
) {
    if (buffer->index + length > buffer->size) {
        buffer->size = PAGE_ALIGN(buffer->size + length);
        buffer->data = realloc(buffer->data, buffer->size);
        hs_assert(buffer->data);
    }

    hs_assert(buffer->size >= buffer->index + length);

    memcpy(buffer->data + buffer->index, data, length);
    buffer->index += length;
}

static
bool
quicksave_read(
    struct quicksave_buffer *buffer,
    uint8_t *data,
    size_t length
) {
    if (buffer->size < buffer->index + length) {
        return (true);
    }

    memcpy(data, buffer->data + buffer->index, length);
    buffer->index += length;
    return (false);
}

/*
** Save the current state of the emulator in the given buffer.
*/
void
quicksave(
    struct gba const *gba,
    uint8_t **data,
    size_t *size
) {
    struct quicksave_buffer buffer;
    size_t i;

    buffer.data = NULL;
    buffer.size = 0;
    buffer.index = 0;

    quicksave_write(&buffer, (uint8_t *)&gba->core, sizeof(gba->core));
    quicksave_write(&buffer, (uint8_t *)&gba->memory, sizeof(gba->memory));
    quicksave_write(&buffer, (uint8_t *)&gba->io, sizeof(gba->io));
    quicksave_write(&buffer, (uint8_t *)&gba->ppu, sizeof(gba->ppu));
    quicksave_write(&buffer, (uint8_t *)&gba->gpio, sizeof(gba->gpio));
    quicksave_write(&buffer, (uint8_t *)&gba->apu, sizeof(gba->apu));
    quicksave_write(&buffer, (uint8_t *)&gba->scheduler.cycles, sizeof(uint64_t));
    quicksave_write(&buffer, (uint8_t *)&gba->scheduler.next_event, sizeof(uint64_t));
    quicksave_write(&buffer, (uint8_t *)&gba->scheduler.events_size, sizeof(size_t));

    // Serialize the scheduler's event list
    for (i = 0; i < gba->scheduler.events_size; ++i) {
        struct scheduler_event *event;

        event = gba->scheduler.events + i;
        quicksave_write(&buffer, (uint8_t *)&event->kind, sizeof(enum sched_event_kind));
        quicksave_write(&buffer, (uint8_t *)&event->active, sizeof(bool));
        quicksave_write(&buffer, (uint8_t *)&event->repeat, sizeof(bool));
        quicksave_write(&buffer, (uint8_t *)&event->at, sizeof(uint64_t));
        quicksave_write(&buffer, (uint8_t *)&event->period, sizeof(uint64_t));
        quicksave_write(&buffer, (uint8_t *)&event->args, sizeof(struct event_args));
    }

    *data = buffer.data;
    *size = buffer.size;
}

/*
** Load a new state for the emulator from the given save state.
*/
bool
quickload(
    struct gba *gba,
    uint8_t *data,
    size_t size
) {
    struct quicksave_buffer buffer;
    size_t i;

    buffer.data = data;
    buffer.size = size;
    buffer.index = 0;

    free(gba->scheduler.events);
    gba->scheduler.events = NULL;
    gba->scheduler.events_size = 0;

    if (
           quicksave_read(&buffer, (uint8_t *)&gba->core, sizeof(gba->core))
        || quicksave_read(&buffer, (uint8_t *)&gba->memory, sizeof(gba->memory))
        || quicksave_read(&buffer, (uint8_t *)&gba->io, sizeof(gba->io))
        || quicksave_read(&buffer, (uint8_t *)&gba->ppu, sizeof(gba->ppu))
        || quicksave_read(&buffer, (uint8_t *)&gba->gpio, sizeof(gba->gpio))
        || quicksave_read(&buffer, (uint8_t *)&gba->apu, sizeof(gba->apu))
        || quicksave_read(&buffer, (uint8_t *)&gba->scheduler.cycles, sizeof(uint64_t))
        || quicksave_read(&buffer, (uint8_t *)&gba->scheduler.next_event, sizeof(uint64_t))
        || quicksave_read(&buffer, (uint8_t *)&gba->scheduler.events_size, sizeof(size_t))
    ) {
        return (true);
    }

    gba->scheduler.events = calloc(gba->scheduler.events_size, sizeof(struct scheduler_event));
    hs_assert(gba->scheduler.events);

    // Serialize the scheduler's event list
    for (i = 0; i < gba->scheduler.events_size; ++i) {
        struct scheduler_event *event;

        event = &gba->scheduler.events[i];
        if (
               quicksave_read(&buffer, (uint8_t *)&event->kind, sizeof(enum sched_event_kind))
            || quicksave_read(&buffer, (uint8_t *)&event->active, sizeof(bool))
            || quicksave_read(&buffer, (uint8_t *)&event->repeat, sizeof(bool))
            || quicksave_read(&buffer, (uint8_t *)&event->at, sizeof(uint64_t))
            || quicksave_read(&buffer, (uint8_t *)&event->period, sizeof(uint64_t))
            || quicksave_read(&buffer, (uint8_t *)&event->args, sizeof(struct event_args))
        ) {
            return (true);
        }
    }

    return (false);
}
