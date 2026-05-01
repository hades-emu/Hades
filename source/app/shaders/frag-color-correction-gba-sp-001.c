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
char const *SHADER_FRAG_COLOR_CORRECTION_GBA_SP_001 = GLSL(
    // Shader that replicates the LCD Colorspace from both Gameboy Advance revision (cicra late 2001) and all
    // Gameboy Advance SP that uses frontlit LCDs, aka AGS-001.
    // This colorspace comes from Panasonic's GBA screen and uses 32-pin connector, and is the most common display you
    // would fine for later GBA and all SP-001.

    layout(location = 0) out vec4 frag_color;

    in vec2 v_uv;

    uniform sampler2D u_screen_map;

    const float darken_screen = 0.5;
    const float target_gamma = 2.2;
    const float display_gamma = 2.2;

    const mat4 profile = mat4(
        0.7875, 0.1175, 0.1775, 0.0,  //red channel
        0.3025, 0.6325, 0.2125, 0.0,  //green channel
        -0.09, 0.25, 0.61, 0.0,  //blue channel
        0.0,  0.0,  0.0,  0.9175   //alpha channel
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
