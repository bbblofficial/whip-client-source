#pragma once

class IHUDElement {
public:
    virtual ~IHUDElement() = default;

    virtual void onInit() = 0;

    virtual void render() = 0;
};
