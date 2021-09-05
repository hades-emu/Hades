/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef MESSAGE_H
# define MESSAGE_H

enum message_type {
    MESSAGE_KEYINPUT,
    MESSAGE_QUICKLOAD,
    MESSAGE_QUICKSAVE,
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

struct message {
    enum message_type type;
    size_t size;
};

struct message_keyinput {
    struct message super;
    enum keyinput key;
    bool pressed;
};

struct message_queue {
    struct message *messages;
    size_t nb_messages;
    size_t size;
};

void message_new(struct gba *gba, struct message *message);
void message_handle_all(struct gba *gba);

# define NEW_MESSAGE_KEYINPUT(_key, _pressed)           \
    ((struct message *)&((struct message_keyinput){     \
        .super = (struct message){                      \
            .size = sizeof(struct message_keyinput),    \
            .type = MESSAGE_KEYINPUT,                   \
        },                                              \
        .key = (_key),                                  \
        .pressed = (_pressed)                           \
    }))

# define NEW_MESSAGE_QUICKSAVE()                        \
    (&((struct message){                                \
        .type = MESSAGE_QUICKSAVE,                      \
        .size = sizeof(struct message),                 \
    }))

# define NEW_MESSAGE_QUICKLOAD()                        \
    (&((struct message){                                \
        .type = MESSAGE_QUICKLOAD,                      \
        .size = sizeof(struct message),                 \
    }))

#endif /* !EVENTS_H */