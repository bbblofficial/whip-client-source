#pragma once

class Cancellable {
    bool cancelled = false;

public:
    bool isCancelled() const {
        return cancelled;
    }

    void setCancelled(const bool cancelled) {
        this->cancelled = cancelled;
    }
};
