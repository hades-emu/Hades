/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include "app/app.h"

/*
** Grey-Scale effect.
*/
char const *SHADER_FRAG_GREY_SCALE = GLSL(
    layout(location = 0) out vec4 frag_color;

    in vec2 v_uv;

    uniform sampler2D u_screen_map;

    void main() {
        vec4 color = texture(u_screen_map, v_uv);
        float avg = (color.r + color.g + color.b) / 3.0;
        frag_color = vec4(avg, avg, avg, 1.0);
    }
);
