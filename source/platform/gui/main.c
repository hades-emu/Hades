/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <GL/glew.h>

#include <cimgui.h>
#include <cimgui_impl.h>

#define SDL_MAIN_HANDLED
#include <SDL2/SDL.h>

#ifdef _MSC_VER
# include <windows.h>
#endif

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#ifdef IMGUI_HAS_IMSTR
# define igBegin igBegin_Str
# define igSliderFloat igSliderFloat_Str
# define igCheckbox igCheckbox_Str
# define igColorEdit3 igColorEdit3_Str
# define igButton igButton_Str
#endif

#include "hades.h"
#include "gba/gba.h"
#include "gba/db.h"
#include "gba/core/arm.h"
#include "gba/core/thumb.h"
#include "platform/gui.h"
#include "utils/fs.h"

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
        "    -b, --bios=PATH                   path pointing to the bios dump (default: \"bios.bin\")\n"
        "        --color=[always|never|auto]   adjust color settings (default: auto)\n"
        "\n"
        "    -h, --help                        print this help and exit\n"
        "    -v, --version                     print the version information and exit\n"
        "",
        name
    );
}

/*
** Parse the given command line arguments.
*/
static
void
args_parse(
    struct app *app,
    int argc,
    char *argv[]
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
            CLI_COLOR,
        };

        static struct option long_options[] = {
            [CLI_HELP]      = { "help",         no_argument,        0,  0 },
            [CLI_VERSION]   = { "version",      no_argument,        0,  0 },
            [CLI_BIOS]      = { "bios",         required_argument,  0,  0 },
            [CLI_COLOR]     = { "color",        optional_argument,  0,  0 },
                              { 0,              0,                  0,  0 }
        };

        c = getopt_long(
            argc,
            argv,
            "hvb:",
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
                        break;
                    case CLI_VERSION: // --version
                        printf("Hades v" HADES_VERSION "\n");
                        exit(EXIT_SUCCESS);
                        break;
                    case CLI_BIOS:
                        app->emulation.bios_path = strdup(optarg);
                        break;
                    case CLI_COLOR: // --color
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
                    default:
                        print_usage(stderr, name);
                        exit(EXIT_FAILURE);
                        break;
                }
                break;
            case 'b':
                app->emulation.bios_path = strdup(optarg);
                break;
            case 'h':
                print_usage(stdout, name);
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                printf("Hades v" HADES_VERSION "\n");
                exit(EXIT_SUCCESS);
                break;
            default:
                print_usage(stderr, name);
                exit(EXIT_FAILURE);
                break;
        }
    }

    switch (argc - optind) {
        case 0:
            break;
        case 1:
            app->emulation.game_path = strdup(argv[optind]);
            break;
        default:
            print_usage(stderr, name);
            exit(EXIT_FAILURE);
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

static
void
gui_audio_callback(
    void *raw_app,
    uint8_t *raw_stream,
    int raw_stream_len
) {
    struct app *app;
    struct gba *gba;
    int16_t *stream;
    size_t len;
    size_t i;

    app = raw_app;
    gba = app->emulation.gba;
    stream = (int16_t *)raw_stream;
    len = raw_stream_len / (2 * sizeof(*stream));

    pthread_mutex_lock(&gba->apu.frontend_channels_mutex);
    for (i = 0; i < len; ++i) {
        stream[0] = apu_rbuffer_pop(&gba->apu.channel_left);
        stream[1] = apu_rbuffer_pop(&gba->apu.channel_right);
        stream += 2;
    }
    pthread_mutex_unlock(&gba->apu.frontend_channels_mutex);
}

/*
** Initialize the SDL, OpenGL and ImGUI.
*/
static
void
gui_init(
    struct app *app
) {
    SDL_AudioSpec want;
    SDL_AudioSpec have;
    ImFontConfig *cfg;
    char const* glsl_version;

    /* Initialize the SDL */
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMECONTROLLER | SDL_INIT_AUDIO) < 0) {
        fprintf(stderr, "Failed to init the SDL: %s\n", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    /* Setup Audio */
    want.freq = 48000;
    want.samples = 2048;
    want.format = AUDIO_S16;
    want.channels = 2;
    want.callback = gui_audio_callback;
    want.userdata = app;

    app->audio_device = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);

    if (!app->audio_device) {
        fprintf(stderr, "Failed to init the audio device: %s\n", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    gui_game_set_audio_settings(app, CYCLES_PER_SECOND / have.freq);

    SDL_PauseAudioDevice(app->audio_device, SDL_FALSE);

    /* Decide which OpenGL version to use */
#if __APPLE__
    // GL 3.2 Core + GLSL 150
    glsl_version = "#version 150";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
#else
    // GL 3.0 + GLSL 130
    glsl_version = "#version 130";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#endif

    /* Prepare OpenGL stuff */
    SDL_SetHint(SDL_HINT_RENDER_DRIVER, "opengl");
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);

    /* High resolution */
    SDL_GetDisplayDPI(0, &app->dpi, NULL, NULL);

#if __APPLE__
    app->gui_scale = 1;
#else
    float dpi_factor;

    dpi_factor = app->dpi / 96.f;
    if (dpi_factor >= (int)dpi_factor + 0.5f) {
        app->gui_scale = (int)dpi_factor + 1;
    } else {
        app->gui_scale = (int)dpi_factor ? (int)dpi_factor : 1;
    }
#endif

    /* Create the window */
    app->window = SDL_CreateWindow(
        "Hades",
        SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED,
        GBA_SCREEN_WIDTH * 3 * app->gui_scale,
        (GBA_SCREEN_HEIGHT * 3 + 19.f) * app->gui_scale ,
        SDL_WINDOW_SHOWN | SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE
    );

    if (!app->window) {
        fprintf(stderr, "Failed to create the window: %s\n", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    /* Create the OpenGL context */
    app->gl_context = SDL_GL_CreateContext(app->window);
    SDL_GL_MakeCurrent(app->window, app->gl_context);

    /* Enable VSync */
    SDL_GL_SetSwapInterval(app->vsync);

    /* Initialize OpenGL */
    if (glewInit()) {
        fprintf(stderr, "Failed to initialize OpenGL.\n");
        exit(EXIT_FAILURE);
    }

    /* Setup ImGui */
    igCreateContext(NULL);
    igStyleColorsDark(NULL);

    /* Set ImGui options */
    app->ioptr = igGetIO();
    app->ioptr->ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;      // Enable Keyboard Controls
    app->ioptr->ConfigFlags |= ImGuiConfigFlags_DockingEnable;          // Enable Docking

    cfg = ImFontConfig_ImFontConfig();
    cfg->SizePixels = 13.f * app->gui_scale;
    cfg->GlyphOffset.y = 13.f * app->gui_scale;
    ImFontAtlas_AddFontDefault(app->ioptr->Fonts, cfg);
    ImGuiStyle_ScaleAllSizes(igGetStyle(), app->gui_scale);

    ImGui_ImplSDL2_InitForOpenGL(app->window, app->gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    /* Create the OpenGL texture that will hold the game's output */
    glGenTextures(1, &app->game_texture);

    /* Setup the game controller stuff */
    app->controller = NULL;
    app->joystick_idx = -1;
    app->controller_connected = false;

    /* Setup the ImGui File Dialog extension */
    app->fs_dialog = IGFD_Create();
    hs_assert(app->fs_dialog);
}

/*
** Close and destroy any resources related to the SDL, OpenGL or ImGUI.
*/
static
void
gui_cleanup(
    struct app *app
) {
    if (app->emulation.backup_file) {
        fclose(app->emulation.backup_file);
    }
    /* Cleanup the ImGui File Dialog extension */
    IGFD_Destroy(app->fs_dialog);

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    igDestroyContext(NULL);

    glDeleteTextures(1, &app->game_texture);

    SDL_GL_DeleteContext(app->gl_context);
    SDL_DestroyWindow(app->window);
    SDL_CloseAudioDevice(app->audio_device);
    SDL_Quit();
}

/*
** Render a single frame of the UI.
*/
static
void
gui_render_frame(
    struct app *app
) {
    ImVec4 bg;

    /* Create the new frame */
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame(app->window);
    igNewFrame();

    /* Render the main menu bar */
    gui_render_menubar(app);

    /* Render the game */
    if (app->emulation.enabled) {
        gui_render_game_fullscreen(app);
    }

    gui_render_errors(app);

    igRender();

    // Change the background color depending on wether the game is active or not
    if (app->emulation.enabled) {
        bg.x = 0.f;
        bg.y = 0.f;
        bg.z = 0.f;
        bg.w = 1.f;
    } else {
        bg.x = 176.f / 255.f;
        bg.y = 124.f / 255.f;
        bg.z = 223.f / 255.f;
        bg.w = 1.00f;
    }

    SDL_GL_MakeCurrent(app->window, app->gl_context);
    glViewport(0, 0, (int)app->ioptr->DisplaySize.x, (int)app->ioptr->DisplaySize.y);
    glClearColor(bg.x, bg.y, bg.z, bg.w);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(igGetDrawData());

    if (app->ioptr->ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
        SDL_Window *backup_current_window;
        SDL_GLContext backup_current_context;

        backup_current_window = SDL_GL_GetCurrentWindow();
        backup_current_context = SDL_GL_GetCurrentContext();
        igUpdatePlatformWindows();
        igRenderPlatformWindowsDefault(NULL,NULL);
        SDL_GL_MakeCurrent(backup_current_window, backup_current_context);
    }

    SDL_GL_SwapWindow(app->window);
}

int
main(
    int argc,
    char *argv[]
) {
    pthread_t logic_thread;
    struct app app;
    uint32_t last_fps_update;

    memset(&app, 0, sizeof(app));
    app.emulation.enabled = false;
    app.emulation.speed = 1;
    app.emulation.color_correction = true;
    app.emulation.gba = malloc(sizeof(*app.emulation.gba));
    hs_assert(app.emulation.gba);
    gba_init(app.emulation.gba);

    gui_load_config(&app);

    args_parse(&app, argc, argv);

    /* Initialize the SDL, OpenGL and ImGUI */
    gui_init(&app);

    /* Set the color correction */
    gui_game_color_correction(&app);

    /* Start the logic thread */
    pthread_create(
        &logic_thread,
        NULL,
        (void *(*)(void *))gba_run,
        app.emulation.gba
    );

    logln(HS_GLOBAL, "Welcome to Hades v" HADES_VERSION);
    logln(HS_GLOBAL, "=========================");
    logln(HS_GLOBAL, "Opengl version: %s%s%s", g_light_magenta, (char*)glGetString(GL_VERSION), g_reset);
    logln(
        HS_GLOBAL,
        "Dpi: %s%f%s, Dpi factor: %s%u%s",
        g_light_magenta,
        app.dpi,
        g_reset,
        g_light_magenta,
        app.gui_scale,
        g_reset
    );

    /* If a game was supplied in the CLI argument, launch it now */
    if (app.emulation.game_path) {
        gui_game_reload(&app);
    }

    app.run = true;
    last_fps_update = SDL_GetTicks();
    while (app.run) {
        SDL_Event event;
        uint32_t now;

        /* Handle all SDL events */
        while (SDL_PollEvent(&event) != 0) {
            ImGui_ImplSDL2_ProcessEvent(&event);

            switch (event.type) {
                case SDL_QUIT: {
                    app.run = false;
                    break;
                };
                case SDL_WINDOWEVENT: {
                    if (event.window.event == SDL_WINDOWEVENT_CLOSE
                        && event.window.windowID == SDL_GetWindowID(app.window)
                    ) {
                        app.run = false;
                    }
                    break;
                };
                case SDL_CONTROLLERDEVICEADDED: {
                    if (!app.controller_connected) {
                        SDL_Joystick *joystick;

                        app.controller = SDL_GameControllerOpen(event.cdevice.which);
                        joystick = SDL_GameControllerGetJoystick(app.controller);
                        app.joystick_idx = SDL_JoystickInstanceID(joystick);
                        app.controller_connected = true;
                        logln(
                            HS_GLOBAL,
                            "Controller \"%s%s%s\" connected.",
                            g_light_magenta,
                            SDL_GameControllerName(app.controller),
                            g_reset
                        );
                    }
                    break;
                };
                case SDL_CONTROLLERDEVICEREMOVED: {
                    if (event.cdevice.which >= 0 && event.cdevice.which == app.joystick_idx) {
                        logln(
                            HS_GLOBAL,
                            "Controller \"%s%s%s\" disconnected.",
                            g_light_magenta,
                            SDL_GameControllerName(app.controller),
                            g_reset
                        );
                        SDL_GameControllerClose(app.controller);
                        app.controller = NULL;
                        app.joystick_idx = -1;
                        app.controller_connected = false;
                    }
                    break;
                };
            }

            /* Transfer SDL events to the game */
            if (app.emulation.enabled && !app.emulation.pause) {
                gui_game_handle_events(&app, &event);
            }
        }

        /* Update the FPS every second */
        if (app.emulation.enabled && !app.emulation.pause) {
            now = SDL_GetTicks();
            if ((now - last_fps_update) >= 1000) {
                app.emulation.fps = atomic_exchange(&app.emulation.gba->framecounter, 0);
                last_fps_update = now;

                /*
                ** We also want to store the content of the backup storage
                ** on the disk every second (if it is dirty).
                */
                gui_game_write_backup(&app);

                /*
                ** We also update the Window's name with the game title
                */
                if (app.emulation.gba->game_entry) {
                    SDL_SetWindowTitle(app.window, app.emulation.gba->game_entry->title);
                } else {
                    SDL_SetWindowTitle(app.window, "Hades");
                }
            }
        }

        /* Render the frame */
        gui_render_frame(&app);
    }

    gui_cleanup(&app);

    gui_save_config(&app);
}