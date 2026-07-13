#include "../../../../../includes/module/impl/combat/throw/ThrowModule.h"
#include <widgets.h>
#include "../../../../../includes/handler/ModuleHandler.h"
#include "../../../../../includes/module/impl/combat/throw/mode/ThrowDebuffMode.h"

void ThrowModule::executeThrowMode(std::unique_ptr<ThrowMode>& mode, int speed, bool enabled, int keybind, bool doubleOption, bool smartMode, bool& keyPressed, JniScope& scope) {
    if (!enabled) return;
    if (keybind == 0) return;

    if (const bool keyCurrentlyPressed = (GetAsyncKeyState(keybind) & 0x8000) != 0; !keyCurrentlyPressed) {
        keyPressed = false;
        return;
    }

    if (keyPressed) {
        return;
    }

    keyPressed = true;

    throwing_.store(true, std::memory_order_release);
    mode->execute(speed, doubleOption, smartMode, nullptr, scope.getEnv());
    throwing_.store(false, std::memory_order_release);
}

void ThrowModule::onUpdate(JniScope& scope) {
    executeThrowMode(potMode, potSpeed, potEnabled, potKeybind, doubleThrow, smartMod, potKeyPressed, scope);
    executeThrowMode(pearlMode, pearlSpeed, pearlEnabled, pearlKeybind, false, false, pearlKeyPressed, scope);
    executeThrowMode(soupMode, soupSpeed, soupEnabled, soupKeybind, doubleUse, smartModSoup, soupKeyPressed, scope);
    executeThrowMode(debuffMode, debuffSpeed, debuffEnabled, debuffKeybind, doubleThrowDebuff, false, debuffKeyPressed, scope);
}

REGISTER_MODULE(ThrowModule, ModuleType::THROW_MODULE)
