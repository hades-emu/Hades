#include "gui/gui.h"

char const *SHADER_VERTEX_COMMON = GLSL(
    layout(location = 0) in vec2 position;
    layout(location = 1) in vec2 uv;

    out vec2 v_uv;

    void main() {
        v_uv = uv;
        gl_Position = vec4(position, 0.0, 1.0);
    }
);
