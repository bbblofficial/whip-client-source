#include "util/RenderMatrixSnapshot.h"
#include <Windows.h>
#include <GL/gl.h>

void RenderMatrixSnapshot::capture() {
    glGetFloatv(GL_PROJECTION_MATRIX, projection_.data());
    glGetFloatv(GL_MODELVIEW_MATRIX, modelview_.data());
    valid_.store(true, std::memory_order_release);
}

bool RenderMatrixSnapshot::getProjection(std::array<float, 16>& out) const {
    if (!valid_.load(std::memory_order_acquire)) return false;
    out = projection_;
    return true;
}

bool RenderMatrixSnapshot::getModelView(std::array<float, 16>& out) const {
    if (!valid_.load(std::memory_order_acquire)) return false;
    out = modelview_;
    return true;
}
