/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#define SDL_MAIN_HANDLED
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS

#include <GL/glew.h>
#include <cimgui.h>
#include <cimgui_impl.h>
#include <nfd.h>
#include "platform/gui/app.h"
#include "gba/gba.h"
#include "hades.h"

void
gui_sdl_video_init(
    struct app *app
) {
    char const *glsl_version;

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

    /* Get the display's DPI */
    SDL_GetDisplayDPI(0, &app->ui.dpi, NULL, NULL);

    /* Setup ImGui DPI and scaling factors */
#if __APPLE__
    /*
    ** On my MacBook (12.3.1) it looks like the system is already scaling the window in a nice, pixel-perfect way.
    **
    ** If we use our scaling on top of it, the windows gets blurry and ugly very quick so we hard-code the scaling to 1 to
    ** avoid that.
    */
    app->ui.scale = 1;
#else
    float dpi_factor;

    dpi_factor = app->ui.dpi / 96.f;
    if (dpi_factor >= (int)dpi_factor + 0.5f) {
        app->ui.scale = (int)dpi_factor + 1;
    } else {
        app->ui.scale = (int)dpi_factor ? (int)dpi_factor : 1;
    }
#endif

    /*
    ** Create the SDL window
    **
    ** The window is resized after the first frame to take into account the height of the menubar,
    ** unknown at this stage.
    ** The size given here is merely a guess as to what the real size will be, hence the magical +19.f for the window's height.
    */
    app->sdl.window = SDL_CreateWindow(
        "Hades",
        SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED,
        GBA_SCREEN_WIDTH * app->video.display_size * app->ui.scale,
        (GBA_SCREEN_HEIGHT * app->video.display_size + 19.f) * app->ui.scale ,
        SDL_WINDOW_SHOWN | SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE
    );

    if (!app->sdl.window) {
        logln(HS_ERROR, "Failed to create the window: %s", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    /* Create the OpenGL context */
    app->sdl.gl_context = SDL_GL_CreateContext(app->sdl.window);
    SDL_GL_MakeCurrent(app->sdl.window, app->sdl.gl_context);

    /* Enable VSync */
    SDL_GL_SetSwapInterval(app->video.vsync);

    /* Initialize OpenGL */
    if (glewInit()) {
        logln(HS_ERROR, "Failed to initialize OpenGL.");
        exit(EXIT_FAILURE);
    }

    /* Setup ImGui */
    igCreateContext(NULL);
    igStyleColorsDark(NULL);

    /* Set ImGui options */
    app->ui.ioptr = igGetIO();
    app->ui.ioptr->ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls

    /* Setup ImGui font size */
    ImFontConfig *cfg;

    cfg = ImFontConfig_ImFontConfig();
    cfg->SizePixels = 13.f * app->ui.scale;
    cfg->GlyphOffset.y = 13.f * app->ui.scale;
    ImFontAtlas_AddFontDefault(app->ui.ioptr->Fonts, cfg);
    ImGuiStyle_ScaleAllSizes(igGetStyle(), app->ui.scale);

    ImGui_ImplSDL2_InitForOpenGL(app->sdl.window, app->sdl.gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    /* Create the OpenGL texture that will hold the game's output */
    glGenTextures(1, &app->sdl.game_texture);

    /* Setup the game controller stuff */
    app->sdl.controller.ptr = NULL;
    app->sdl.controller.connected = false;
    app->sdl.controller.joystick.idx = -1;

    /* Setup the Native File Dialog extension */
    NFD_Init();
}

void
gui_sdl_video_cleanup(
    struct app *app
) {
    /* Cleanup the Native File Dialog extension */
    NFD_Quit();

    // Shutdown ImGui
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    igDestroyContext(NULL);

    // Cleanup OpenGL
    glDeleteTextures(1, &app->sdl.game_texture);
    SDL_GL_DeleteContext(app->sdl.gl_context);

    // Close the Wingowd
    SDL_DestroyWindow(app->sdl.window);
}

void
gui_sdl_video_render_frame(
    struct app *app
) {
    /* Create the new frame */
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame(app->sdl.window);
    igNewFrame();

    /* Render the ImGui stuff */

    gui_win_menubar(app);

    if (app->emulation.started) {
        gui_win_game(app);
    }

    gui_win_error(app);

    /* Render the imGui frame */
    igRender();

    SDL_GL_MakeCurrent(app->sdl.window, app->sdl.gl_context);
    glViewport(0, 0, (int)app->ui.ioptr->DisplaySize.x, (int)app->ui.ioptr->DisplaySize.y);

    /* Change the background color if the game is running */
    if (app->emulation.started) {
        glClearColor(0.f, 0.f, 0.f, 1.f);
    } else {
        glClearColor(176.f / 255.f, 124.f / 255.f, 223.f / 255.f, 1.f);
    }

    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(igGetDrawData());

    if (app->ui.ioptr->ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
        SDL_Window *backup_current_window;
        SDL_GLContext backup_current_context;

        backup_current_window = SDL_GL_GetCurrentWindow();
        backup_current_context = SDL_GL_GetCurrentContext();
        igUpdatePlatformWindows();
        igRenderPlatformWindowsDefault(NULL,NULL);
        SDL_GL_MakeCurrent(backup_current_window, backup_current_context);
    }

    SDL_GL_SwapWindow(app->sdl.window);
}