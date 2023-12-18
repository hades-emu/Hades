/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <getopt.h>
#include <stdio.h>
#include "hades.h"
#include "app/app.h"
#include "compat.h"

/*
** Print the program's usage.
*/
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
        "    -b, --bios=PATH                    Path pointing to the bios dump (default: \"bios.bin\")\n"
        "    -c, --config=PATH                  Path pointing to the configuration file (default: \"config.json\")\n"
        "        --color=[always|never|auto]    Adjust color settings (default: auto)\n"
#ifdef WITH_DEBUGGER
        "        --without-gui                  Disable any gui\n"
#endif
        "\n"
        "    -h, --help                         Print this help and exit\n"
        "    -v, --version                      Print the version information and exit\n"
        "",
        name
    );
}

/*
** Parse the given command line arguments.
*/
void
app_args_parse(
    struct app *app,
    int argc,
    char * const argv[]
) {
    char const *name;
    uint32_t color;

    color = 0;
    name = argv[0];
    while (true) {
        int c;
        int option_index;

        enum cli_options {
            CLI_HELP = 0,
            CLI_VERSION,
            CLI_BIOS,
            CLI_CONFIG,
            CLI_COLOR,
            CLI_WITHOUT_GUI,
        };

        static struct option long_options[] = {
            [CLI_HELP]          = { "help",         no_argument,        0,  0 },
            [CLI_VERSION]       = { "version",      no_argument,        0,  0 },
            [CLI_BIOS]          = { "bios",         required_argument,  0,  0 },
            [CLI_CONFIG]        = { "config",       required_argument,  0,  0 },
            [CLI_COLOR]         = { "color",        optional_argument,  0,  0 },
#ifdef WITH_DEBUGGER
            [CLI_WITHOUT_GUI]   = { "without-gui",  no_argument,        0,  0 },
#endif
                                  { 0,              0,                  0,  0 }
        };

        c = getopt_long(
            argc,
            argv,
            "hvb:c:",
            long_options,
            &option_index
        );

        if (c == -1) {
            break;
        }

        switch (c) {
            case 0: {
                switch (option_index) {
                    case CLI_HELP: { // --help
                        print_usage(stdout, name);
                        exit(EXIT_SUCCESS);
                        break;
                    };
                    case CLI_VERSION: { // --version
                        printf("Hades v" HADES_VERSION "\n");
                        exit(EXIT_SUCCESS);
                        break;
                    };
                    case CLI_BIOS: { // --bios
                        app->args.bios_path = optarg;
                        break;
                    };
                    case CLI_CONFIG: { // --config
                        app->args.config_path = optarg;
                        break;
                    };
                    case CLI_COLOR: { // --color
                        if (optarg) {
                            if (!strcmp(optarg, "auto")) {
                                color = 0;
                                break;
                            } else if (!strcmp(optarg, "never")) {
                                color = 1;
                                break;
                            } else if (!strcmp(optarg, "always")) {
                                color = 2;
                                break;
                            } else {
                                print_usage(stderr, name);
                                exit(EXIT_FAILURE);
                            }
                        } else {
                            color = 0;
                        }
                        break;
                    };
                    case CLI_WITHOUT_GUI: {
                        app->args.with_gui = false;
                        break;
                    };
                    default: {
                        print_usage(stderr, name);
                        exit(EXIT_FAILURE);
                        break;
                    };
                }
                break;
            };
            case 'b': {
                app->args.bios_path = optarg;
                break;
            };
            case 'c': {
                app->args.config_path = optarg;
                break;
            };
            case 'h': {
                print_usage(stdout, name);
                exit(EXIT_SUCCESS);
                break;
            };
            case 'v': {
                printf("Hades v" HADES_VERSION "\n");
                exit(EXIT_SUCCESS);
                break;
            };
            default: {
                print_usage(stderr, name);
                exit(EXIT_FAILURE);
                break;
            };
        }
    }

    switch (argc - optind) {
        case 0: {
            break;
        };
        case 1: {
            app->args.rom_path = argv[optind];
            break;
        };
        default: {
            print_usage(stderr, name);
            exit(EXIT_FAILURE);
        };
    }

    switch (color) {
        case 0:
            if (!hs_isatty(1)) {
                disable_colors();
            }
            break;
        case 1:
            disable_colors();
            break;
    }
}
