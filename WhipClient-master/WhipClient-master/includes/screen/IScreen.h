#ifndef ISCREEN_H
#define ISCREEN_H

#include "ScreenType.h"
#include <Windows.h>

class Gui;

class IScreen {
public:
    virtual ~IScreen() = default;

    virtual void onInit() const = 0;
    virtual void onDestroy() const = 0;

    virtual void drawing(const RECT& rect, const Gui* handler) const = 0;

    virtual ScreenType getType() const = 0;
};

#endif
