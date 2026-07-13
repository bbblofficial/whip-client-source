#ifndef IGUICUSTOMRENDER_H
#define IGUICUSTOMRENDER_H

#include <memory>

class c_widgets;

class IGuiCustomRender {
public:
    IGuiCustomRender() = default;

    virtual ~IGuiCustomRender() {}

    enum IGuiCustomRenderType {
        OVERRIDE,
        NONE,
    };

    virtual IGuiCustomRenderType getRenderType() const = 0;

    virtual void onRender(const std::unique_ptr<c_widgets>&) = 0;
    virtual void onFullRender(const std::unique_ptr<c_widgets>&) = 0;
    virtual void onRenderConditional(const std::unique_ptr<c_widgets>&) = 0;
};

#endif
