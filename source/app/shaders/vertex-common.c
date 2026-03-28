/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include "app/app.h"

char const *SHADER_VERTEX_COMMON = GLSL(
    layout(location = 0) in vec2 position;
    layout(location = 1) in vec2 uv;

    out vec2 v_uv;

    void
    main(
        void
    ) {
        v_uv = uv;
        gl_Position = vec4(position, 0.0, 1.0);
    }
);
