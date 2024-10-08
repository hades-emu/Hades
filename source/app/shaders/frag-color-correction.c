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
** Color correction algorithm by Higan Emu.
**
** Reference:
**   - https://github.com/higan-emu/emulation-articles/tree/master/video/color-emulation
*/
char const *SHADER_FRAG_COLOR_CORRECTION = GLSL(
    layout(location = 0) out vec4 frag_color;

    in vec2 v_uv;

    uniform sampler2D u_screen_map;

    void
    main(
        void
    ) {
        vec4 color = texture(u_screen_map, v_uv);
        float lcd_gamma = 4.0;
        float out_gamma = 2.2;

        color.rgb = pow(color.rgb, vec3(lcd_gamma));

        color.rgb = vec3(
            1.000 * color.r + 0.196 * color.g + 0.000 * color.b,
            0.039 * color.r + 0.902 * color.g + 0.118 * color.b,
            0.196 * color.r + 0.039 * color.g + 0.863 * color.b
        );

        color.rgb = pow(color.rgb, vec3(1.0 / out_gamma));

        frag_color = vec4(color.rgb, 1.0);
    }
);
