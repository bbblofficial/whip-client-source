#pragma once

#include <jni.h>
#include "util/mathutils.h"

struct BacktrackTarget {
    int entityId = -1;
    Vector3d position{0, 0, 0};
    Vector3d lastPosition{0, 0, 0};
    Vector3d newPosition{0, 0, 0};
    int serverPosX = 0;
    int serverPosY = 0;
    int serverPosZ = 0;
    int posRotationIncrements = 0;
    long long targetTime = 0;
    bool valid = false;

    void clear() {
        entityId = -1;
        valid = false;
        position = {0, 0, 0};
        lastPosition = {0, 0, 0};
        newPosition = {0, 0, 0};
        serverPosX = 0;
        serverPosY = 0;
        serverPosZ = 0;
        posRotationIncrements = 0;
    }
};

struct BTPositionSample {
    double x, y, z;
    int serverPosX, serverPosY, serverPosZ;
    bool fromTeleport;
    long long timestamp;


    [[nodiscard]] double grimX() const { return static_cast<double>(serverPosX) / 32.0; }
    [[nodiscard]] double grimY() const {
        double base = static_cast<double>(serverPosY) / 32.0;
        return fromTeleport ? base + 0.015625 : base;
    }
    [[nodiscard]] double grimZ() const { return static_cast<double>(serverPosZ) / 32.0; }
};

struct SmoothQueuedPacket {
    jobject packet;
    long long timestamp;
};
