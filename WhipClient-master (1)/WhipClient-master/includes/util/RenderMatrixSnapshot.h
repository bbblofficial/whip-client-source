#pragma once

#include <array>
#include <atomic>

class RenderMatrixSnapshot {
public:
    static RenderMatrixSnapshot& get() {
        static RenderMatrixSnapshot inst;
        return inst;
    }

    void capture();

    bool valid() const { return valid_.load(std::memory_order_acquire); }

    bool getProjection(std::array<float, 16>& out) const;
    bool getModelView(std::array<float, 16>& out) const;

private:
    RenderMatrixSnapshot() = default;
    std::array<float, 16> projection_{};
    std::array<float, 16> modelview_{};
    std::atomic<bool> valid_{false};
};
