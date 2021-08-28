/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef EVENTS_H
# define EVENTS_H

enum event_type {
    EVENT_KEYINPUT,
    EVENT_QUICKLOAD,
    EVENT_QUICKSAVE,
};

enum keyinput {
    KEY_A,
    KEY_B,
    KEY_L,
    KEY_R,
    KEY_UP,
    KEY_DOWN,
    KEY_RIGHT,
    KEY_LEFT,
    KEY_START,
    KEY_SELECT,
};

struct event {
    enum event_type type;
    size_t size;
};

struct event_keyinput {
    struct event;
    enum keyinput key;
    bool pressed;
};

struct event_queue {
    struct event *events;
    size_t nb_events;
    size_t size;
};

void event_new(struct gba *gba, struct event *event);
void event_handle_all(struct gba *gba);

# define NEW_EVENT_KEYINPUT(_key, _pressed)             \
    ((struct event *)&((struct event_keyinput){         \
        .type = EVENT_KEYINPUT,                         \
        .size = sizeof(struct event_keyinput),          \
        .key = (_key),                                  \
        .pressed = (_pressed)                           \
    }))

# define NEW_EVENT_QUICKSAVE()                          \
    (&((struct event){                                  \
        .type = EVENT_QUICKSAVE,                        \
        .size = sizeof(struct event),                   \
    }))

# define NEW_EVENT_QUICKLOAD()                          \
    (&((struct event){                                  \
        .type = EVENT_QUICKLOAD,                        \
        .size = sizeof(struct event),                   \
    }))

#endif /* !EVENTS_H */