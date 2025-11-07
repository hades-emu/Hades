/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <GL/glew.h>
#include <cimgui.h>
#include <cimgui_impl.h>
#include <nfd.h>
#include <math.h>

#include "hades.h"
#include "app/app.h"
#include "gba/gba.h"

static GLuint build_shader_program(char const *name, char const *frag_path, char const *vertex_path);

void
app_sdl_video_init(
    struct app *app
) {
    char const *glsl_version;
    SDL_DisplayMode mode;
    uint32_t win_flags;
    int err;

    memset(&mode, 0, sizeof(mode));

    // Decide which OpenGL version to use
#if defined(IMGUI_IMPL_OPENGL_ES2)
    // GL ES 2.0 + GLSL 100 (WebGL 1.0)
    glsl_version = "#version 100";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 2);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#elif defined(IMGUI_IMPL_OPENGL_ES3)
    // GL ES 3.0 + GLSL 300 es (WebGL 2.0)
    glsl_version = "#version 300 es";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#elif defined(__APPLE__)
    // GL 3.2 Core + GLSL 150
    glsl_version = "#version 150";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG); // Always required on Mac
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

    // Prepare OpenGL stuff
    SDL_SetHint(SDL_HINT_RENDER_DRIVER, "opengl");
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);

    win_flags = SDL_WINDOW_HIDDEN;
    win_flags |= SDL_WINDOW_OPENGL;
    win_flags |= SDL_WINDOW_RESIZABLE;
    win_flags |= SDL_WINDOW_HIGH_PIXEL_DENSITY;

    if (app->settings.video.display_mode == DISPLAY_MODE_BORDERLESS_FULLSCREEN) {
        win_flags |= SDL_WINDOW_FULLSCREEN;
    }

    // Create the SDL window
    // The size is currently arbitrary as we need to know the window's display and its content scale to accurately
    // calculate the final size.
    // This also explains why the window is created hidden.
    app->sdl.window = SDL_CreateWindow("Hades", GBA_SCREEN_WIDTH, GBA_SCREEN_HEIGHT, win_flags );
    if (!app->sdl.window) {
        logln(HS_ERROR, "Failed to create the window: %s", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    // Set initial values for the game and window areas.
    app->ui.display.win.width = GBA_SCREEN_WIDTH;
    app->ui.display.win.height = GBA_SCREEN_HEIGHT;
    app_win_game_refresh_game_area(app);

    // Create the OpenGL context
    app->gfx.gl_context = SDL_GL_CreateContext(app->sdl.window);
    SDL_GL_MakeCurrent(app->sdl.window, app->gfx.gl_context);

    // Enable VSync
    SDL_SetRenderVSync(SDL_GetRenderer(app->sdl.window), app->settings.video.vsync ? 1 : SDL_RENDERER_VSYNC_DISABLED);

    // Center the window
    SDL_SetWindowPosition(app->sdl.window, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED);

    // Initialize OpenGL
    err = glewInit();
    if (err != GLEW_OK && err != GLEW_ERROR_NO_GLX_DISPLAY) {
        logln(HS_ERROR, "Failed to initialize OpenGL.");
        exit(EXIT_FAILURE);
    }

    // Setup ImGui
    igCreateContext(NULL);
    igStyleColorsDark(NULL);

    // Set ImGui options
    app->ui.ioptr = igGetIO_Nil();
    app->ui.ioptr->ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
    app->ui.ioptr->IniFilename = NULL;

    ImGui_ImplSDL3_InitForOpenGL(app->sdl.window, app->gfx.gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Copy the default style so we can easily rescale ImGui to something different
    memcpy(&app->ui.default_style, igGetStyle(), sizeof(*igGetStyle()));

    // Update the display scale to match the window's display scale
    app_sdl_video_update_scale(app);

    // Build all the available shaders
    app->gfx.program_color_correction = build_shader_program("color_correction", SHADER_FRAG_COLOR_CORRECTION, SHADER_VERTEX_COMMON);
    app->gfx.program_grey_scale = build_shader_program("grey_scale", SHADER_FRAG_GREY_SCALE, SHADER_VERTEX_COMMON);
    app->gfx.program_lcd_grid_with_rgb_stripes = build_shader_program("lcd_grid_with_rgb_stripes", SHADER_FRAG_LCD_GRID_WITH_RGB_STRIPES, SHADER_VERTEX_COMMON);
    app->gfx.program_lcd_grid = build_shader_program("lcd_grid", SHADER_FRAG_LCD_GRID, SHADER_VERTEX_COMMON);

    // Create the OpenGL objects required to build the pipeline
    glGenTextures(1, &app->gfx.game_texture);
    glGenTextures(1, &app->gfx.pixel_color_texture);
    glGenTextures(1, &app->gfx.pixel_scaling_texture);
    glGenFramebuffers(1, &app->gfx.fbo);
    glGenVertexArrays(1, &app->gfx.vao);
    glGenBuffers(1, &app->gfx.vbo);

    float vertices[] = {
        // position   | UV coord
        -1., 1.,        0., 1.,     // Top left
        1., 1.,         1., 1.,     // Top right
        1., -1.,        1., 0.,     // Bottom right
        1., -1.,        1., 0.,     // Bottom right
        -1., -1.,       0., 0.,     // Bottom left
        -1., 1.,        0., 1.,     // Top left
    };

    // Setup the OpenGL objects
    glBindVertexArray(app->gfx.vao);
    glBindBuffer(GL_ARRAY_BUFFER, app->gfx.vbo);
    glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_STATIC_DRAW);
    glVertexAttribPointer(0, 2, GL_FLOAT, false, 4 * sizeof(float), 0); // position
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(1, 2, GL_FLOAT, false, 4 * sizeof(float), (void *)(2 * sizeof(float))); // UV
    glEnableVertexAttribArray(1);

    // Build the OpenGL pipeline.
    app_sdl_video_rebuild_pipeline(app);

    // Setup the game gamepad stuff
    app->sdl.gamepad.ptr = NULL;
    app->sdl.gamepad.connected = false;
    app->sdl.gamepad.joystick.idx = -1;

    // Setup the Native File Dialog extension
    NFD_Init();

    // Now that initialization is finished, we can render a fake, invisible frame.
    // This will be used to have an accurate size for the menubar if it's pinned.
    if (app->settings.video.menubar_mode == MENUBAR_MODE_PINNED) {
        app_sdl_video_render_frame(app);
    }

    // We can now resize the window as we now have all the information needed to compute its correct and final size.
    app_sdl_video_resize_window(app);

    // And finally we show the window
    SDL_ShowWindow(app->sdl.window);
    SDL_SyncWindow(app->sdl.window);
}

void
app_sdl_video_rebuild_pipeline(
    struct app *app
) {
    GLint texture_filter;

    switch (app->settings.video.texture_filter) {
        case TEXTURE_FILTER_LINEAR: texture_filter = GL_LINEAR; break;
        case TEXTURE_FILTER_NEAREST: texture_filter = GL_NEAREST; break;
        default: texture_filter = GL_NEAREST; break;
    }

    // Setup the input texture
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, app->gfx.game_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, texture_filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, texture_filter);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(
        GL_TEXTURE_2D,
        0,
        GL_RGBA,
        GBA_SCREEN_WIDTH,
        GBA_SCREEN_HEIGHT,
        0,
        GL_RGBA,
        GL_UNSIGNED_BYTE,
        NULL
    );

    switch (app->settings.video.pixel_color_filter) {
        case PIXEL_COLOR_FILTER_COLOR_CORRECTION: {
            app->gfx.pixel_color_program = app->gfx.program_color_correction;
            break;
        };
        case PIXEL_COLOR_FILTER_GREY_SCALE: {
            app->gfx.pixel_color_program = app->gfx.program_grey_scale;
            break;
        };
        default: {
            app->gfx.pixel_color_program = 0;
            break;
        };
    }

    // Setup the pixel color texture
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, app->gfx.pixel_color_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, texture_filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, texture_filter);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(
        GL_TEXTURE_2D,
        0,
        GL_RGBA,
        GBA_SCREEN_WIDTH,
        GBA_SCREEN_HEIGHT,
        0,
        GL_RGBA,
        GL_UNSIGNED_BYTE,
        NULL
    );

    switch (app->settings.video.pixel_scaling_filter) {
        case PIXEL_SCALING_FILTER_LCD_GRID: {
            app->gfx.pixel_scaling_program = app->gfx.program_lcd_grid;
            app->gfx.pixel_scaling_size = 3;
            break;
        };
        case PIXEL_SCALING_FILTER_LCD_GRID_WITH_RGB_STRIPES: {
            app->gfx.pixel_scaling_program = app->gfx.program_lcd_grid_with_rgb_stripes;
            app->gfx.pixel_scaling_size = 3;
            break;
        };
        default: {
            app->gfx.pixel_scaling_program = 0;
            app->gfx.pixel_scaling_size = 1;
            break;
        };
    }

    // Setup the pixel scaling texture
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, app->gfx.pixel_scaling_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, texture_filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, texture_filter);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(
        GL_TEXTURE_2D,
        0,
        GL_RGBA,
        GBA_SCREEN_WIDTH * app->gfx.pixel_scaling_size,
        GBA_SCREEN_HEIGHT * app->gfx.pixel_scaling_size,
        0,
        GL_RGBA,
        GL_UNSIGNED_BYTE,
        NULL
    );

    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glBindTexture(GL_TEXTURE_2D, 0);
}

static
GLuint
build_shader_program(
    char const *name,
    char const *frag_src,
    char const *vertex_src
) {
    GLuint program;
    GLuint frag;
    GLuint vertex;
    GLint status;
    GLint len;

    // Create the program
    program = glCreateProgram();

    // Compile the fragment shader
    frag = glCreateShader(GL_FRAGMENT_SHADER);
    len = strlen(frag_src);
    glShaderSource(frag, 1, &frag_src, &len);
    glCompileShader(frag);

    // Check the fragment shader compiled correctly
    glGetShaderiv(frag, GL_COMPILE_STATUS, &status);
    if (status != GL_TRUE) {
        GLint log_len;
        GLchar *error;

        log_len = 0;
        glGetShaderiv(frag, GL_INFO_LOG_LENGTH, &log_len);

        error = calloc(log_len, 1);
        hs_assert(error);

        glGetShaderInfoLog(frag, log_len, &log_len, error);

        panic(
            HS_ERROR,
            "Failed to compile the \"%s%s%s/fragment%s\" shader:\n"
            "====== BEGIN ======\n"
            "%s"
            "======  END  ======",
            g_bold,
            g_magenta,
            name,
            g_reset,
            error
        );
    }

    // Attach the fragment shader to the program
    glAttachShader(program, frag);

    // Compile the vertex shader
    vertex = glCreateShader(GL_VERTEX_SHADER);
    len = strlen(vertex_src);
    glShaderSource(vertex, 1, &vertex_src, &len);
    glCompileShader(vertex);

    // Check the vertex shader compiled correctly
    glGetShaderiv(vertex, GL_COMPILE_STATUS, &status);
    if (status != GL_TRUE) {
        GLint log_len;
        GLchar *error;

        log_len = 0;
        glGetShaderiv(vertex, GL_INFO_LOG_LENGTH, &log_len);

        error = calloc(log_len, 1);
        hs_assert(error);

        glGetShaderInfoLog(vertex, log_len, &log_len, error);

        panic(
            HS_ERROR,
            "Failed to compile the \"%s%s%s/vertex%s\" shader:\n"
            "====== BEGIN ======\n"
            "%s"
            "======  END  ======",
            g_bold,
            g_magenta,
            name,
            g_reset,
            error
        );
    }

    // Attach the vertex shader to the program
    glAttachShader(program, vertex);

    // Link the program
    glLinkProgram(program);
    glGetShaderiv(program, GL_LINK_STATUS, &status);
    if (status != GL_TRUE) {
        panic(HS_ERROR, "Failed to link shader.");
    }

    // Detach and delete both shaders
    glDetachShader(program, frag);
    glDetachShader(program, vertex);
    glDeleteShader(frag);
    glDeleteShader(vertex);

    return program;
}

void
app_sdl_video_cleanup(
    struct app *app
) {
    /* Cleanup the Native File Dialog extension */
    NFD_Quit();

    // Shutdown ImGui
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL3_Shutdown();
    igDestroyContext(NULL);

    // Cleanup OpenGL
    glDeleteProgram(app->gfx.program_color_correction);
    glDeleteProgram(app->gfx.program_grey_scale);
    glDeleteProgram(app->gfx.program_lcd_grid);
    glDeleteProgram(app->gfx.program_lcd_grid_with_rgb_stripes);
    glDeleteBuffers(1, &app->gfx.vbo);
    glDeleteVertexArrays(1, &app->gfx.vbo);
    glDeleteFramebuffers(1, &app->gfx.fbo);
    glDeleteTextures(1, &app->gfx.game_texture);
    glDeleteTextures(1, &app->gfx.pixel_color_texture);
    glDeleteTextures(1, &app->gfx.pixel_scaling_texture);
    SDL_GL_DestroyContext(app->gfx.gl_context);

    // Close the Window
    SDL_DestroyWindow(app->sdl.window);
}

void
app_sdl_video_render_frame(
    struct app *app
) {
    /* Create the new frame */
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL3_NewFrame();
    igNewFrame();

    /* Render the ImGui stuff */

    app_win_menubar(app);

    if (app->emulation.is_started) {
        app_win_game(app);
    }

    if (app->ui.settings.open) {
        app_win_settings(app);

        // One day we will set this variable only when a setting is modified, or even better: have a "Apply/Cancel"
        // button that will save (or not) the settings accordingly; but for now, we will have to do with that :(
        app->save_config_on_exit = true;
    }

    app_win_notifications(app);

    /* Render the imGui frame */
    igRender();

    SDL_GL_MakeCurrent(app->sdl.window, app->gfx.gl_context);
    glViewport(0, 0, (int)app->ui.ioptr->DisplaySize.x, (int)app->ui.ioptr->DisplaySize.y);

    /* Change the background color if the game is running */
    if (app->emulation.is_started) {
        glClearColor(0.f, 0.f, 0.f, 1.f);
    } else {
        glClearColor(176.f / 255.f, 124.f / 255.f, 223.f / 255.f, 1.f);
    }

    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(igGetDrawData());

    SDL_GL_SwapWindow(app->sdl.window);
}

/*
** Resize the window to match the size chosen in the settings, taking into account the display's content scale.
*/
void
app_sdl_video_resize_window(
    struct app *app
) {
    uint32_t w;
    uint32_t h;

    // Calculate the desired width and height in **screen coordinates**, not pixels, hence why we
    // divide by the display's scale.
    w = round((float)(GBA_SCREEN_WIDTH * app->settings.video.display_size) / app->ui.display_content_scale);
    h = round((float)(GBA_SCREEN_HEIGHT * app->settings.video.display_size) / app->ui.display_content_scale);

    // If relevant, expand the window by the size of the menubar
    h += app->settings.video.menubar_mode == MENUBAR_MODE_PINNED ? app->ui.menubar.size.y : 0;

    SDL_SetWindowSize(app->sdl.window, w, h);
}

/*
** Update the UI scale (and everything that depends on it).
**
** Currently this includes the ImGui fonts and style.
**
** https://wiki.libsdl.org/SDL3/README-highdpi
*/
void
app_sdl_video_update_scale(
    struct app *app
) {
    ImGuiStyle *style;

    style = igGetStyle();

    // Retrieve the content scale
    // This function being called when the window's display is changed, we have to refresh the cached value.
    app->ui.display_content_scale = SDL_GetDisplayContentScale(SDL_GetDisplayForWindow(app->sdl.window));
    app->ui.scale = app->settings.video.autodetect_scale ? app->ui.display_content_scale : app->settings.video.scale;

    // Restore the default style
    memcpy(style, &app->ui.default_style, sizeof(struct ImGuiStyle));

    // Scale the style
    ImGuiStyle_ScaleAllSizes(style, app->ui.scale);
    style->FontScaleDpi = app->ui.scale;
}

void
app_sdl_video_update_display_mode(
    struct app *app
) {
    switch (app->settings.video.display_mode) {
        case DISPLAY_MODE_BORDERLESS_FULLSCREEN: {
            SDL_SetWindowFullscreen(app->sdl.window, true);
            break;
        };
        case DISPLAY_MODE_WINDOW: {
            SDL_SetWindowFullscreen(app->sdl.window, false);
            app_sdl_video_resize_window(app);
            break;
        };
        default: {
            panic(HS_INFO, "Invalid display mode %u", app->settings.video.display_mode);
        };
    }
}

void
app_sdl_video_update_win_title(
    struct app const *app
) {
    if (app->emulation.is_started && app->emulation.game_entry && app->emulation.game_entry->title) {
        SDL_SetWindowTitle(app->sdl.window, app->emulation.game_entry->title);
    } else {
        SDL_SetWindowTitle(app->sdl.window, "Hades");
    }
}
