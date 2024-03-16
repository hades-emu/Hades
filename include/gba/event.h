/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#pragma once

#include "gba/gba.h"

/*
** Messages
*/

enum message_kind {
    MESSAGE_EXIT,
    MESSAGE_RESET,
    MESSAGE_RUN,
    MESSAGE_PAUSE,
    MESSAGE_STOP,
    MESSAGE_KEY,
    MESSAGE_QUICKSAVE,
    MESSAGE_QUICKLOAD,
    MESSAGE_SETTINGS,

#ifdef WITH_DEBUGGER
    MESSAGE_FRAME,
    MESSAGE_TRACE,
    MESSAGE_STEP_IN,
    MESSAGE_STEP_OVER,
    MESSAGE_SET_BREAKPOINTS_LIST,
    MESSAGE_SET_WATCHPOINTS_LIST,
#endif

    MESSAGE_MAX,
    MESSAGE_MIN = 0,
    MESSAGE_LEN = MESSAGE_MAX + 1,
};

struct message {
    struct event_header header;
};

struct message_reset {
    struct event_header header;
    struct launch_config config;
};

struct message_settings {
    struct event_header header;
    struct gba_settings settings;
};

struct message_key {
    struct event_header header;
    enum keys key;
    bool pressed;
};

struct message_quickload {
    struct event_header header;
    uint8_t *data;
    size_t size;
};

#ifdef WITH_DEBUGGER

struct message_step {
    struct event_header header;
    size_t count;
};

struct message_trace {
    struct event_header header;
    size_t count;
    void (*tracer_cb)(void *);
    void *arg;
};

struct message_set_breakpoints_list {
    struct event_header header;
    struct breakpoint *breakpoints;
    size_t len;
};

struct message_set_watchpoints_list {
    struct event_header header;
    struct watchpoint *watchpoints;
    size_t len;
};

struct message_frame {
    struct event_header header;
    size_t count;
};

#endif

/*
** Notifications
*/

enum notification_kind {
    NOTIFICATION_RESET,
    NOTIFICATION_RUN,
    NOTIFICATION_PAUSE,
    NOTIFICATION_STOP,

    // Only sent to the frontend
    NOTIFICATION_QUICKSAVE,
    NOTIFICATION_QUICKLOAD,

    // Only sent to the debuger
#ifdef WITH_DEBUGGER
    NOTIFICATION_BREAKPOINT,
    NOTIFICATION_WATCHPOINT,
    NOTIFICATION_BREAKPOINTS_LIST_SET,
    NOTIFICATION_WATCHPOINTS_LIST_SET,
#endif

    NOTIFICATION_MAX,
    NOTIFICATION_MIN = 0,
    NOTIFICATION_LEN = NOTIFICATION_MAX + 1,
};

struct notification {
    struct event_header header;
};

struct notification_quicksave {
    struct event_header header;
    uint8_t *data;
    size_t size;
};

#ifdef WITH_DEBUGGER

struct notification_breakpoint {
    struct event_header header;
    uint32_t addr;
};

struct notification_watchpoint {
    struct event_header header;
    uint32_t addr;
    struct {
        uint32_t addr;
        uint32_t val;
        uint32_t size;
        bool write;
    } access;
};

#endif
