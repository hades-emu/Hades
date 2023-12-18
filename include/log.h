/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#pragma once

/*
** The different modules one can log to.
*/
enum modules {
    HS_INFO      = 0,

    HS_ERROR,
    HS_WARNING,

    HS_CORE,
    HS_IO,
    HS_VIDEO,
    HS_DMA,
    HS_IRQ,
    HS_MEMORY,
    HS_TIMER,

    HS_DEBUG,

    HS_END,
};

/*
** A set of global strings pointing to ANSI control sequences to format the terminal.
** They can also be set to the empty string if coloration is disabled.
*/
extern char const *g_reset;
extern char const *g_bold;

extern char const *g_red;
extern char const *g_green;
extern char const *g_yellow;
extern char const *g_blue;
extern char const *g_magenta;
extern char const *g_cyan;
extern char const *g_light_gray;
extern char const *g_dark_gray;
extern char const *g_light_red;
extern char const *g_light_green;
extern char const *g_light_yellow;
extern char const *g_light_blue;
extern char const *g_light_magenta;
extern char const *g_light_cyan;
extern char const *g_white;

extern bool g_verbose[HS_END];
extern bool g_verbose_global;

static char const * const modules_str[] = {
    [HS_INFO]       = " INFO  ",
    [HS_ERROR]      = " ERROR ",
    [HS_WARNING]    = " WARN  ",
    [HS_CORE]       = " CORE  ",
    [HS_IO]         = " IO    ",
    [HS_VIDEO]      = " VIDEO ",
    [HS_DMA]        = " DMA   ",
    [HS_IRQ]        = " IRQ   ",
    [HS_MEMORY]     = " MEM   ",
    [HS_TIMER]      = " TIMER ",
    [HS_DEBUG]      = " DEBUG ",
};

/* log.c */
void logln(enum modules module, char const *fmt, ...) __attribute__ ((format (printf, 2, 3)));
void panic(enum modules module, char const *fmt, ...) __attribute__ ((format (printf, 2, 3))) __attribute__((noreturn));
void unimplemented(enum modules module, char const *fmt, ...) __attribute__ ((format (printf, 2, 3))) __attribute__((noreturn));
void disable_colors(void);
