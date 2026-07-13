#include "util/BlurShaders.h"

namespace BlurShaders {

    const char* BLUR_VERTEX_SHADER = R"(
#version 330 core
layout (location = 0) in vec2 aPos;
layout (location = 1) in vec2 aTexCoord;

out vec2 TexCoords;

void main()
{
    gl_Position = vec4(aPos.x, aPos.y, 0.0, 1.0);
    TexCoords = aTexCoord;
}
)";

    const char* BLUR_FRAGMENT_SHADER = R"(
#version 330 core
out vec4 FragColor;
in vec2 TexCoords;

uniform sampler2D image;
uniform float blurRadius;
uniform vec2 blurDirection;

void main()
{
    vec2 texelSize = 1.0 / textureSize(image, 0);
    vec3 result = vec3(0.0);

    float weights[13] = float[](
        0.0561, 0.1353, 0.2780, 0.4868, 0.7261, 0.9231, 1.0,
        0.9231, 0.7261, 0.4868, 0.2780, 0.1353, 0.0561
    );

    float weightSum = 0.0;
    for (int i = 0; i < 13; i++) {
        weightSum += weights[i];
    }

    for (int i = -6; i <= 6; i++) {
        vec2 offset = texelSize * blurDirection * float(i) * blurRadius;
        result += texture(image, TexCoords + offset).rgb * weights[i + 6];
    }

    FragColor = vec4(result / weightSum, 1.0);
}
)";

    const char* QUAD_VERTEX_SHADER = R"(
#version 330 core
layout (location = 0) in vec2 aPos;
layout (location = 1) in vec2 aTexCoord;

out vec2 TexCoords;

uniform mat4 projection;

void main()
{
    gl_Position = projection * vec4(aPos.x, aPos.y, 0.0, 1.0);
    TexCoords = aTexCoord;
}
)";

    const char* QUAD_FRAGMENT_SHADER = R"(
#version 330 core
out vec4 FragColor;
in vec2 TexCoords;

uniform sampler2D blurredTexture;
uniform float alpha;

void main()
{
    vec4 texColor = texture(blurredTexture, TexCoords);
    FragColor = vec4(texColor.rgb, texColor.a * alpha);
}
)";

}
