#pragma once

#include <cmath>


struct MotionSimulator {

    static constexpr double GRAVITY            = 0.08;
    static constexpr double Y_FRICTION         = 0.9800000190734863;
    static constexpr double AIR_FRICTION_XZ    = 0.91;
    static constexpr double GROUND_SLIPPERINESS = 0.6;
    static constexpr double GROUND_FRICTION    = 0.546;
    static constexpr double MOTION_THRESHOLD   = 0.005;
    static constexpr double ACCEL_DENOMINATOR  = 0.16277136;
    static constexpr double BASE_SPEED         = 0.10000000149011612;
    static constexpr double SPRINT_SPEED       = 0.13000000312924387;
    static constexpr double AIR_ACCEL          = 0.02;
    static constexpr double AIR_ACCEL_SPRINT   = 0.026;
    static constexpr int    MAX_SIM_TICKS      = 40;


    double posX = 0, posY = 0, posZ = 0;
    double motionX = 0, motionY = 0, motionZ = 0;
    double groundY = 0;
    float  targetYaw = 0;
    bool   onGround = false;
    bool   sprinting = false;
    bool   active = false;
    int    ticksSinceKB = 0;

    void reset() {
        posX = posY = posZ = 0;
        motionX = motionY = motionZ = 0;
        groundY = 0;
        targetYaw = 0;
        onGround = false;
        sprinting = false;
        active = false;
        ticksSinceKB = 0;
    }


    void applyKnockback(int rawVelX, int rawVelY, int rawVelZ,
                         double currentX, double currentY, double currentZ,
                         bool currentOnGround, float entityYaw, bool entitySprinting) {
        motionX = static_cast<double>(rawVelX) / 8000.0;
        motionY = static_cast<double>(rawVelY) / 8000.0;
        motionZ = static_cast<double>(rawVelZ) / 8000.0;

        posX = currentX;
        posY = currentY;
        posZ = currentZ;
        onGround = currentOnGround;
        groundY = currentOnGround ? currentY : currentY;
        targetYaw = entityYaw;
        sprinting = entitySprinting;
        active = true;
        ticksSinceKB = 0;
    }


    void updateTargetState(float yaw, bool isSprinting, bool isOnGround) {
        targetYaw = yaw;
        sprinting = isSprinting;
        if (isOnGround && !onGround) {

            groundY = posY;
        }
    }


    void reconcile(double serverX, double serverY, double serverZ) {
        if (!active) return;
        posX = serverX;
        posY = serverY;
        posZ = serverZ;
        if (onGround) groundY = serverY;
    }


    void simulateTick() {
        if (!active) return;
        ++ticksSinceKB;


        if (std::abs(motionX) < MOTION_THRESHOLD) motionX = 0;
        if (std::abs(motionY) < MOTION_THRESHOLD) motionY = 0;
        if (std::abs(motionZ) < MOTION_THRESHOLD) motionZ = 0;


        double friction = onGround ? GROUND_FRICTION : AIR_FRICTION_XZ;


        double accel;
        if (onGround) {
            double speed = sprinting ? SPRINT_SPEED : BASE_SPEED;
            double f3 = friction * friction * friction;
            accel = speed * (ACCEL_DENOMINATOR / f3);
        } else {
            accel = sprinting ? AIR_ACCEL_SPRINT : AIR_ACCEL;
        }


        {
            double moveForward = 0.98;
            double fwdScaled = moveForward * accel;

            float yawRad = targetYaw * static_cast<float>(3.14159265358979323846 / 180.0);
            double sinYaw = std::sin(static_cast<double>(yawRad));
            double cosYaw = std::cos(static_cast<double>(yawRad));

            motionX += -fwdScaled * sinYaw;
            motionZ +=  fwdScaled * cosYaw;
        }


        posX += motionX;
        posY += motionY;
        posZ += motionZ;


        if (posY <= groundY && motionY <= 0) {
            posY = groundY;
            motionY = 0;
            onGround = true;
        } else {
            onGround = false;
        }


        motionY -= GRAVITY;

        motionY *= Y_FRICTION;


        motionX *= friction;
        motionZ *= friction;


        if (ticksSinceKB > MAX_SIM_TICKS ||
            (onGround && std::abs(motionX) < MOTION_THRESHOLD &&
                         std::abs(motionZ) < MOTION_THRESHOLD)) {
            active = false;
        }
    }

    [[nodiscard]] double horizontalSpeed() const {
        return std::sqrt(motionX * motionX + motionZ * motionZ);
    }
};
