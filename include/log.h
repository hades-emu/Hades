/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#pragma once

/*
** The different modules one can log to.
*/
enum modules {
    HS_INFO      = 0,

    HS_ERROR,
    HS_WARN,

    HS_CORE,
    HS_IO,
    HS_VIDEO,
    HS_DMA,
    HS_IRQ,
    HS_MEMORY,
    HS_TIMER,
    HS_CHEAT,

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

extern char const * const module_names[];

/* log.c */
void hs_logln(enum modules module, char const *fmt, ...) __attribute__ ((format (printf, 2, 3)));
void hs_panic(enum modules module, char const *fmt, ...) __attribute__ ((format (printf, 2, 3))) __attribute__((noreturn));
void hs_unimplemented(enum modules module, char const *fmt, ...) __attribute__ ((format (printf, 2, 3))) __attribute__((noreturn));
void hs_disable_colors(void);

#ifdef WITH_DEBUGGER
#define hs_dbgln(...) hs_logln(__VA_ARGS__)
#else
#define hs_dbgln(...) if (0) { hs_logln(__VA_ARGS__); }
#endif
