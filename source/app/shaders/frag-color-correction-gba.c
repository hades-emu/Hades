/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include "app/app.h"

/*
** Color correction algorithm by Pokefan531 and Hunterk.
**
** Shader Modified: Pokefan531
** Color Mangler
** Author: hunterk
** License: Public domain
**
** Reference:
**  - https://github.com/Pokefan531/Handheld-Colorspace-Shaders/blob/main/handheld/shaders/color/gba-color.slang
*/
char const *SHADER_FRAG_COLOR_CORRECTION_GBA = GLSL(
    // Shader that replicates the LCD Colorspace from the Gameboy Advance early revisions (up to late 2001) that uses
    // Sharp's manufactured displays.
    // GBA's Sharp displays are the ones that are found on many 40-pin connectors.

    layout(location = 0) out vec4 frag_color;

    in vec2 v_uv;

    uniform sampler2D u_screen_map;

    const float darken_screen = 0.5;
    const float target_gamma = 2.2;
    const float display_gamma = 2.2;

    const mat4 profile = mat4(
        0.93, 0.125, 0.19, 0.0,     //red channel
        0.2125, 0.60, 0.21, 0.0,    //green channel
        -0.1425, 0.275, 0.6, 0.0,   //blue channel
        0.0,  0.0,  0.0,  0.875     //alpha channel
    );

    void
    main(
        void
    ) {
        float lum = profile[3].w;

        // our adjustments need to happen in linear gamma
        vec4 screen = pow(texture(u_screen_map, v_uv), vec4(target_gamma + darken_screen)).rgba;

        screen = clamp(screen * lum, 0.0, 1.0);
        screen = profile * screen;

        frag_color = pow(screen, vec4(1.0 / display_gamma));
    }
);
