#include "wrapper/CVarsUpdater.h"

void CVarsUpdater::Initialize() {
    ModelView.fill(0.0);
    Projection.fill(0.0);
    Viewport.fill(0);

    for (int i = 0; i < 4; ++i) {
        ModelView[i * 4 + i] = 1.0;
        Projection[i * 4 + i] = 1.0;
    }

    ScreenWidth = 0;
    ScreenHeight = 0;
    MatricesValid = false;
    theLocalPlayer = nullptr;
}

void CVarsUpdater::PreUpdate() {
}

void CVarsUpdater::Update(void* player) {
    theLocalPlayer = player;
}
