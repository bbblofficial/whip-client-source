#pragma once

#include <cmath>
#include <array>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace RotationHelper {

    struct Rotation {
        float yaw = 0.0f;
        float pitch = 0.0f;
    };

    inline float wrapAngle(float angle) {
        while (angle > 180.0f) angle -= 360.0f;
        while (angle < -180.0f) angle += 360.0f;
        return angle;
    }

    inline Rotation getRotationTo(double fromX, double fromY, double fromZ,
                                   double toX, double toY, double toZ) {
        double dx = toX - fromX;
        double dy = toY - fromY;
        double dz = toZ - fromZ;
        double distXZ = std::sqrt(dx * dx + dz * dz);

        float yaw = (float)(std::atan2(dz, dx) * 180.0 / M_PI) - 90.0f;
        float pitch = (float)(-(std::atan2(dy, distXZ) * 180.0 / M_PI));

        return { wrapAngle(yaw), std::clamp(pitch, -90.0f, 90.0f) };
    }

    inline Rotation getDelta(float currentYaw, float currentPitch,
                              float targetYaw, float targetPitch) {
        return {
            wrapAngle(targetYaw - currentYaw),
            wrapAngle(targetPitch - currentPitch)
        };
    }

    inline Rotation smooth(float currentYaw, float currentPitch,
                            float targetYaw, float targetPitch,
                            float hSpeed, float vSpeed) {
        float dy = wrapAngle(targetYaw - currentYaw);
        float dp = wrapAngle(targetPitch - currentPitch);

        float smoothedYaw = dy * std::clamp(hSpeed, 0.0f, 1.0f);
        float smoothedPitch = dp * std::clamp(vSpeed, 0.0f, 1.0f);

        return { smoothedYaw, smoothedPitch };
    }

    inline bool isInFov2D(float deltaYaw, float deltaPitch, float hFov, float vFov) {
        return std::abs(deltaYaw) <= hFov && std::abs(deltaPitch) <= vFov;
    }

    inline bool isInFov3D(float deltaYaw, float deltaPitch, float fov) {
        float angle = std::sqrt(deltaYaw * deltaYaw + deltaPitch * deltaPitch);
        return angle <= fov;
    }

    inline float get3DAngle(float deltaYaw, float deltaPitch) {
        return std::sqrt(deltaYaw * deltaYaw + deltaPitch * deltaPitch);
    }

    inline Rotation addNoise(float deltaYaw, float deltaPitch, float strength) {
        if (strength <= 0.0f) return { deltaYaw, deltaPitch };
        float noiseY = ((float)(rand() % 1000) / 1000.0f - 0.5f) * 2.0f * strength;
        float noiseP = ((float)(rand() % 1000) / 1000.0f - 0.5f) * 2.0f * strength;
        return { deltaYaw + noiseY, deltaPitch + noiseP };
    }
}
