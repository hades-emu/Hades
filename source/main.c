/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <stdatomic.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "hades.h"
#include "gba.h"
#include "core/arm.h"
#include "core/thumb.h"
#include "scheduler.h"
#include "ppu.h"
#include "memory.h"
#include "debugger.h"
#include "compat.h"

/*
** A global, atomic variable used to signal other threads it is time to stop and exit.
*/
atomic_bool g_stop;

/*
** A global, atomic variable used to signal other threads the execution should be interrupted.
*/
atomic_bool g_interrupt;

/*
** A global variable used to indicate the verbosity of all the different log levels.
** Restricted to the logic thread only.
*/
bool g_verbose_global = true;
bool g_verbose[HS_END] = {
    [HS_GLOBAL] = true,
    [HS_ERROR] = true,
    [HS_MEMORY] = true,
};

/*
** The signal handler, used to set `g_interrupt` to true and go back to
** the debugger.
*/
__unused
static
void
sighandler(
    int signal
) {
    g_interrupt = true;
}

static
void
print_usage(
    FILE *file,
    char const *name
) {
    fprintf(
        file,
        "Usage: %s [OPTION]... ROM\n"
        "\n"
        "Options:\n"
#if ENABLE_DEBUGGER
        "    -d, --debugger                    enable the debugger\n"
#endif
#if ENABLE_SDL2
        "        --headless                    disable any graphical output\n"
        "    -s, --scale=SIZE                  scale the window by SIZE\n"
#endif
        "        --color=[always|never|auto]   adjust color settings (default: auto)\n"
        "\n"
        "    -h, --help                        print this help and exit\n"
        "        --version                     print the version information and exit\n"
        "",
        name
    );
}

static
char const *
args_parse(
    int argc,
    char *argv[],
    struct options *options
) {
    char const *name;

    name = argv[0];
    while (true) {
        int c;
        int option_index;

        enum cli_options {
            CLI_HELP = 0,
            CLI_VERSION,
            CLI_COLOR,
#if ENABLE_SDL2
            CLI_HEADLESS,
            CLI_SCALE,
#endif
#if ENABLE_DEBUGGER
            CLI_DEBUGGER,
#endif
        };

        static struct option long_options[] = {
            [CLI_HELP]      = { "help",         no_argument,        0,  0 },
            [CLI_VERSION]   = { "version",      no_argument,        0,  0 },
            [CLI_COLOR]     = { "color",        optional_argument,  0,  0 },
#if ENABLE_SDL2
            [CLI_HEADLESS]  = { "headless",     no_argument,        0,  0 },
            [CLI_SCALE]     = { "scale",        required_argument,  0,  0 },
#endif
#if ENABLE_DEBUGGER
            [CLI_DEBUGGER]  = { "debugger",     no_argument,        0,  0 },
#endif
                              { 0,              0,                  0,  0 }
        };

        c = getopt_long(
            argc,
            argv,
#if ENABLE_SDL2
            "s:"
#endif
#if ENABLE_DEBUGGER
            "d"
#endif
            "h",
            long_options,
            &option_index
        );

        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                switch (option_index) {
                    case CLI_HELP: // --help
                        print_usage(stdout, name);
                        exit(EXIT_SUCCESS);
                    case CLI_VERSION: // --version
                        printf("Hades v0.0.1\n");
                        exit(EXIT_SUCCESS);
                        break;
                    case CLI_COLOR: // --color
                        if (optarg) {
                            if (!strcmp(optarg, "auto")) {
                                options->color = 0;
                                break;
                            } else if (!strcmp(optarg, "never")) {
                                options->color = 1;
                                break;
                            } else if (!strcmp(optarg, "always")) {
                                options->color = 2;
                                break;
                            } else {
                                print_usage(stderr, name);
                                exit(EXIT_FAILURE);
                            }
                        } else {
                            options->color = 0;
                        }
#if ENABLE_SDL2
                    case CLI_HEADLESS: // --headless
                        options->headless = true;
                        break;
                    case CLI_SCALE: // --scale
                        options->scale = strtoul(optarg, NULL, 10);
                        break;
#endif
#if ENABLE_DEBUGGER
                    case CLI_DEBUGGER: // --debugger
                        options->debugger = true;
                        break;
#endif
                    default:
                        print_usage(stderr, name);
                        exit(EXIT_FAILURE);
                        break;
                }
                break;
            case 'd':
                options->debugger = true;
                break;
            case 'h':
                print_usage(stdout, name);
                exit(EXIT_SUCCESS);
                break;
            case 's':
                options->scale = strtoul(optarg, NULL, 10);
                break;
            default:
                print_usage(stderr, name);
                exit(EXIT_FAILURE);
                break;
        }
    }

    if (argc - optind != 1) {
        print_usage(stderr, name);
        exit(EXIT_FAILURE);
    }

    if (options->scale < 1 || options->scale > 15) {
        fprintf(stderr, "Error: the UI scale must be between 1 and 15.\n");
        exit(EXIT_FAILURE);
    }

    switch (options->color) {
        case 0:
            if (!hs_isatty(1)) {
                disable_colors();
            }
            break;
        case 1:
            disable_colors();
            break;
    }

    return (argv[optind]);
}

static
void *
logic_thread_main(
    struct gba *gba
) {
#if ENABLE_DEBUGGER
    /*
    ** If we use a debugger, initialize it and enter the debugger's REPL.
    ** Otherwise, loop until the application is closed.
    */
    if (gba->options.debugger) {
        signal(SIGINT, &sighandler);
        debugger_init(gba);
        debugger_repl(gba);
        debugger_destroy(gba);
    } else {
        sched_run_forever(gba);
    }
#else
    sched_run_forever(gba);
#endif
    return (NULL);
}

int
main(
    int argc,
    char *argv[]
) {
    char const *rom;
    struct gba *gba;

    /* First, initialize the GBA system */

    gba = malloc(sizeof(*gba));
    hs_assert(gba != NULL);

    memset(gba, 0, sizeof(*gba));
    gba->input.raw = 0x3FF; // Every button set to "released"
    gba->options.scale = 3; // Default window scale

    rom = args_parse(argc, argv, &gba->options); /* Parse arguments. NOTE: this function exits on failure. */

    pthread_mutex_init(&gba->framebuffer_mutex, NULL);
    pthread_mutex_init(&gba->input_mutex, NULL);
    pthread_mutex_init(&gba->emulator_mutex, NULL);

    core_arm_decode_insns();
    core_thumb_decode_insns();

    sched_init(&gba->scheduler);
    mem_init(&gba->memory);
    io_init(&gba->io);
    ppu_init(gba);

    /* Load the BIOS. NOTE: this function exits on failure. */
    mem_load_bios(&gba->memory, "bios.bin");

    /* Load the given ROM. NOTE: this function exits on failure. */
    mem_load_rom(gba, rom);

    core_init(gba);

#if ENABLE_SDL2
    /*
    ** If graphics are required, move the logic to another thread
    ** and enter the SDL main loop
    */
    if (!gba->options.headless) {
        pthread_t logic_thread;

        pthread_create(
            &logic_thread,
            NULL,
            (void *(*)(void *))
            logic_thread_main,
            gba
        );
        sdl_render_loop(gba);
        pthread_join(logic_thread, NULL);
    } else {
        logic_thread_main(gba);
    }
#else
    logic_thread_main(gba);
#endif

    sched_cleanup(&gba->scheduler);
    free(gba);

    return (EXIT_SUCCESS);
}
