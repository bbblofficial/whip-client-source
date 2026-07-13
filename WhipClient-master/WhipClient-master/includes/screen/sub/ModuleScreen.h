#ifndef MODULESCREEN_H
#define MODULESCREEN_H

#include "screen/base/BaseScreen.h"

class ModuleScreen : public BaseScreen {
public:
    ModuleScreen() = default;
    ~ModuleScreen() override = default;

    void onInit() const override {}
    void onDestroy() const override {}

    ScreenType getType() const override {
        return MODULE;
    }

    void drawing(const RECT& rect, const Gui* handler) const override;
};

#endif
