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
#include "SDL_video.h"
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

    // Prepare OpenGL stuff
    SDL_SetHint(SDL_HINT_RENDER_DRIVER, "opengl");
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);

    // Get the display's DPI
    SDL_GetDisplayDPI(0, &app->ui.display_dpi, NULL, NULL);

    // Get the display's refresh rate
    SDL_GetDisplayMode(0, 0, &mode);
    app->ui.display_refresh_rate = (uint32_t)mode.refresh_rate;

    // Assume a scale of 1 before the window is initialized.
    // We can't properly retrieve the display's scale before we create the window
    app->ui.scale = 1;

    // Initialise the window area.
    //
    // The window is resized after the first frame to take into account the new scale and
    // the height of the menubar, unknown at this stage.
    //
    // The size given here is merely a guess as to what the real size will be, hence the magical +19.f for the window's height.
    app->ui.menubar.size.y = app->settings.video.menubar_mode == MENUBAR_MODE_FIXED_ABOVE_GAME ? 19.f * app->ui.scale : 0.f;
    app->ui.display.win.width = GBA_SCREEN_WIDTH * app->settings.video.display_size;
    app->ui.display.win.height = GBA_SCREEN_HEIGHT * app->settings.video.display_size + app->ui.menubar.size.y;
    app_win_game_refresh_game_area(app);

    win_flags = SDL_WINDOW_SHOWN | SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI;

    switch (app->settings.video.display_mode) {
        case DISPLAY_MODE_BORDERLESS:       win_flags |= SDL_WINDOW_FULLSCREEN_DESKTOP; break;
        case DISPLAY_MODE_FULLSCREEN:       win_flags |= SDL_WINDOW_FULLSCREEN; break;
        default:                            break;
    }

    // Create the SDL window
    app->sdl.window = SDL_CreateWindow(
        "Hades",
        SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED,
        app->ui.display.win.width,
        app->ui.display.win.height,
        win_flags
    );

    if (!app->sdl.window) {
        logln(HS_ERROR, "Failed to create the window: %s", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    // Create the OpenGL context
    app->gfx.gl_context = SDL_GL_CreateContext(app->sdl.window);
    SDL_GL_MakeCurrent(app->sdl.window, app->gfx.gl_context);

    // Enable VSync
    SDL_GL_SetSwapInterval(app->settings.video.vsync);

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
    app->ui.ioptr = igGetIO();
    app->ui.ioptr->ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
    app->ui.ioptr->IniFilename = NULL;

    ImGui_ImplSDL2_InitForOpenGL(app->sdl.window, app->gfx.gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Copy the default style so we can easily rescale ImGui to something different
    memcpy(&app->ui.default_style, igGetStyle(), sizeof(*igGetStyle()));

    // Update all scale-related objects, such as the ImGui fonts and style.
    app->ui.display_scale = app_sdl_video_calculate_scale(app);
    app->ui.scale = app->settings.video.autodetect_scale ? app->ui.display_scale : app->settings.video.scale;
    app_sdl_video_update_scale(app);

    // Request a resize to ensure the window matches the new scale
    app->ui.display.resize_request_timer = DEFAULT_RESIZE_TIMER;

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

    // Setup the game controller stuff
    app->sdl.controller.ptr = NULL;
    app->sdl.controller.connected = false;
    app->sdl.controller.joystick.idx = -1;

    // Setup the Native File Dialog extension
    NFD_Init();
}

/*
** Calculate the UI's scale by dividing the window's size in logical points by its size in pixels.
*/
float
app_sdl_video_calculate_scale(
    struct app *app
) {
    // MacOS handles most of the heavy lifting on its own
#if defined(__APPLE__)
    return 1.0f;
#else
    int screen_w;
    int pixel_w;

    // Same thing with Wayland, most of the heavy lifting is done by the compositor
    if (getenv("WAYLAND_DISPLAY")) {
        return 1.0f;
    } else {
        SDL_GetWindowSize(app->sdl.window, &screen_w, NULL);
        SDL_GL_GetDrawableSize(app->sdl.window, &pixel_w, NULL);

        return ((float)pixel_w / (float)screen_w);
    }
#endif
}

/*
** Resize the window to match the size choosen in the settings and the monitor's scale.
*/
void
app_sdl_video_resize_window(
    struct app *app
) {
    uint32_t w;
    uint32_t h;

    // Calculate the desired width and height in **screen coordinates**, not pixels, hence why we
    // divide by the display's scale.
    w = round((float)(GBA_SCREEN_WIDTH * app->settings.video.display_size) / app->ui.display_scale);
    h = round((float)(GBA_SCREEN_HEIGHT * app->settings.video.display_size) / app->ui.display_scale);

    // If relevant, expand the window by the size of the menubar
    h += app->settings.video.menubar_mode == MENUBAR_MODE_FIXED_ABOVE_GAME ? app->ui.menubar.size.y : 0;

    SDL_SetWindowSize(app->sdl.window, w, h);
}

/*
** Update the UI scale (and everything that depends on it).
**
** Currently this includes the ImGui fonts and style.
*/
void
app_sdl_video_update_scale(
    struct app *app
) {
    ImFontConfig *cfg;
    struct ImGuiStyle *style;

    ImFontAtlas_Clear(app->ui.ioptr->Fonts);

    cfg = ImFontConfig_ImFontConfig();
    cfg->SizePixels = round(13.f * app->ui.scale);
    cfg->GlyphOffset.y = round(13.f * app->ui.scale);
    cfg->RasterizerDensity = round(app->ui.scale * 2.f);
    app->ui.fonts.normal = ImFontAtlas_AddFontDefault(app->ui.ioptr->Fonts, cfg);

    cfg = ImFontConfig_ImFontConfig();
    cfg->SizePixels = round(13.f * app->ui.scale * 3.);
    cfg->GlyphOffset.y =  round(13.f * app->ui.scale * 3.);
    cfg->RasterizerDensity = round(app->ui.scale * 2.f);
    app->ui.fonts.big = ImFontAtlas_AddFontDefault(app->ui.ioptr->Fonts, cfg);

    ImFontAtlas_Build(app->ui.ioptr->Fonts);
    ImGui_ImplOpenGL3_DestroyDeviceObjects();

    style = igGetStyle();

    // Restore default style size
    style->WindowPadding = app->ui.default_style.WindowPadding;
    style->WindowRounding = app->ui.default_style.WindowRounding;
    style->WindowMinSize = app->ui.default_style.WindowMinSize;
    style->ChildRounding = app->ui.default_style.ChildRounding;
    style->PopupRounding = app->ui.default_style.PopupRounding;
    style->FramePadding = app->ui.default_style.FramePadding;
    style->FrameRounding = app->ui.default_style.FrameRounding;
    style->ItemSpacing = app->ui.default_style.ItemSpacing;
    style->ItemInnerSpacing = app->ui.default_style.ItemInnerSpacing;
    style->CellPadding = app->ui.default_style.CellPadding;
    style->TouchExtraPadding = app->ui.default_style.TouchExtraPadding;
    style->IndentSpacing = app->ui.default_style.IndentSpacing;
    style->ColumnsMinSpacing = app->ui.default_style.ColumnsMinSpacing;
    style->ScrollbarSize = app->ui.default_style.ScrollbarSize;
    style->ScrollbarRounding = app->ui.default_style.ScrollbarRounding;
    style->GrabMinSize = app->ui.default_style.GrabMinSize;
    style->GrabRounding = app->ui.default_style.GrabRounding;
    style->LogSliderDeadzone = app->ui.default_style.LogSliderDeadzone;
    style->TabRounding = app->ui.default_style.TabRounding;
    style->TabMinWidthForCloseButton = (style->TabMinWidthForCloseButton != FLT_MAX) ? app->ui.default_style.TabMinWidthForCloseButton : FLT_MAX;
    style->SeparatorTextPadding = app->ui.default_style.SeparatorTextPadding;
    style->DisplayWindowPadding = app->ui.default_style.DisplayWindowPadding;
    style->DisplaySafeAreaPadding = app->ui.default_style.DisplaySafeAreaPadding;
    style->MouseCursorScale = app->ui.default_style.MouseCursorScale;

    ImGuiStyle_ScaleAllSizes(style, app->ui.scale);
}

void
app_sdl_video_update_display_mode(
    struct app *app
) {
    uint32_t win_flags;

    switch (app->settings.video.display_mode) {
        case DISPLAY_MODE_FULLSCREEN:           win_flags = SDL_WINDOW_FULLSCREEN; break;
        case DISPLAY_MODE_BORDERLESS:           win_flags = SDL_WINDOW_FULLSCREEN_DESKTOP; break;
        case DISPLAY_MODE_WINDOWED: {
            win_flags = 0;
            app->ui.display.resize_request_timer = true;
            break;
        };
        default: {
            panic(HS_INFO, "Invalid display mode %u", app->settings.video.display_mode);
            break;
        }
    }

    SDL_SetWindowFullscreen(app->sdl.window, win_flags);
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
    ImGui_ImplSDL2_Shutdown();
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
    SDL_GL_DeleteContext(app->gfx.gl_context);

    // Close the Wingowd
    SDL_DestroyWindow(app->sdl.window);
}

void
app_sdl_video_render_frame(
    struct app *app
) {
    /* Create the new frame */
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame();
    igNewFrame();

    /* Render the ImGui stuff */

    app_win_menubar(app);

    if (app->emulation.is_started) {
        app_win_game(app);
    }

    if (app->ui.settings.open) {
        app_win_settings(app);
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
