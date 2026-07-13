#pragma once

#include <array>

class CVarsUpdater {
public:
    static inline std::array<double, 16> ModelView{};
    static inline std::array<double, 16> Projection{};
    static inline std::array<int, 4> Viewport{};

    static inline int ScreenWidth = 0;
    static inline int ScreenHeight = 0;

    static inline bool MatricesValid = false;

    static inline void* theLocalPlayer = nullptr;

    static void Initialize();
    static void PreUpdate();
    static void Update(void* player);
};
