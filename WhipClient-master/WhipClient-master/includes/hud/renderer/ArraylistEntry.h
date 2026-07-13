#pragma once

#include <string>
#include <imgui.h>
#include <Windows.h>

inline void secureStringZero(std::string& str) {

    if (str.capacity() > 0) {
        SecureZeroMemory(str.data(), str.capacity());
    }
    str.clear();
}

struct ArraylistEntry {
    std::string name;
    std::string flags;

    float targetWidth = 0.0f;
    float currentWidth = 0.0f;
    float animationProgress = 0.0f;

    float boundingBoxMin = 0;
    float boundingBoxMax = 0;
    float boundingBoxMinY = 0;
    float boundingBoxMaxY = 0;

    float boundingBarMin = 0;
    float boundingBarMax = 0;
    float boundingBarMinY = 0;
    float boundingBarMaxY = 0;

    ImVec2 renderPos = ImVec2(0, 0);

    std::string id;

    ArraylistEntry() = default;

    ArraylistEntry(const std::string& entryName, const std::string& entryFlags, const std::string& entryId = std::string())
        : name(entryName), flags(entryFlags), id(entryId.empty() ? entryName : entryId) {}

    ArraylistEntry(const ArraylistEntry& other)
        : name(other.name), flags(other.flags),
          targetWidth(other.targetWidth), currentWidth(other.currentWidth),
          animationProgress(other.animationProgress),
          boundingBoxMin(other.boundingBoxMin), boundingBoxMax(other.boundingBoxMax),
          boundingBoxMinY(other.boundingBoxMinY), boundingBoxMaxY(other.boundingBoxMaxY),
          boundingBarMin(other.boundingBarMin), boundingBarMax(other.boundingBarMax),
          boundingBarMinY(other.boundingBarMinY), boundingBarMaxY(other.boundingBarMaxY),
          renderPos(other.renderPos), id(other.id) {}

    ArraylistEntry& operator=(const ArraylistEntry& other) {
        if (this != &other) {
            secureStringZero(name);
            secureStringZero(flags);
            secureStringZero(id);
            name = other.name;
            flags = other.flags;
            id = other.id;
            targetWidth = other.targetWidth;
            currentWidth = other.currentWidth;
            animationProgress = other.animationProgress;
            boundingBoxMin = other.boundingBoxMin;
            boundingBoxMax = other.boundingBoxMax;
            boundingBoxMinY = other.boundingBoxMinY;
            boundingBoxMaxY = other.boundingBoxMaxY;
            boundingBarMin = other.boundingBarMin;
            boundingBarMax = other.boundingBarMax;
            boundingBarMinY = other.boundingBarMinY;
            boundingBarMaxY = other.boundingBarMaxY;
            renderPos = other.renderPos;
        }
        return *this;
    }

    ArraylistEntry(ArraylistEntry&& other) noexcept
        : name(std::move(other.name)), flags(std::move(other.flags)),
          targetWidth(other.targetWidth), currentWidth(other.currentWidth),
          animationProgress(other.animationProgress),
          boundingBoxMin(other.boundingBoxMin), boundingBoxMax(other.boundingBoxMax),
          boundingBoxMinY(other.boundingBoxMinY), boundingBoxMaxY(other.boundingBoxMaxY),
          boundingBarMin(other.boundingBarMin), boundingBarMax(other.boundingBarMax),
          boundingBarMinY(other.boundingBarMinY), boundingBarMaxY(other.boundingBarMaxY),
          renderPos(other.renderPos), id(std::move(other.id)) {

        secureStringZero(other.name);
        secureStringZero(other.flags);
        secureStringZero(other.id);
    }

    ArraylistEntry& operator=(ArraylistEntry&& other) noexcept {
        if (this != &other) {
            secureStringZero(name);
            secureStringZero(flags);
            secureStringZero(id);
            name = std::move(other.name);
            flags = std::move(other.flags);
            id = std::move(other.id);

            secureStringZero(other.name);
            secureStringZero(other.flags);
            secureStringZero(other.id);
            targetWidth = other.targetWidth;
            currentWidth = other.currentWidth;
            animationProgress = other.animationProgress;
            boundingBoxMin = other.boundingBoxMin;
            boundingBoxMax = other.boundingBoxMax;
            boundingBoxMinY = other.boundingBoxMinY;
            boundingBoxMaxY = other.boundingBoxMaxY;
            boundingBarMin = other.boundingBarMin;
            boundingBarMax = other.boundingBarMax;
            boundingBarMinY = other.boundingBarMinY;
            boundingBarMaxY = other.boundingBarMaxY;
            renderPos = other.renderPos;
        }
        return *this;
    }

    void clear() {
        secureStringZero(name);
        secureStringZero(flags);
        secureStringZero(id);

        targetWidth = 0.0f;
        currentWidth = 0.0f;
        animationProgress = 0.0f;
        boundingBoxMin = 0;
        boundingBoxMax = 0;
        boundingBoxMinY = 0;
        boundingBoxMaxY = 0;
        boundingBarMin = 0;
        boundingBarMax = 0;
        boundingBarMinY = 0;
        boundingBarMaxY = 0;
        renderPos = ImVec2(0, 0);
    }

    ~ArraylistEntry() {
        clear();
    }

};
