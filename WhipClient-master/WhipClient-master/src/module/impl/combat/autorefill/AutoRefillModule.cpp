#include "../../../../../includes/module/impl/combat/autorefill/AutoRefillModule.h"

#include "../../../../../includes/handler/ModuleHandler.h"
#include "../../../../../includes/module/impl/combat/autorefill/mode/AutoRefillMode.h"
#include "../../../../../includes/module/impl/combat/autorefill/mode/AutoRefillBlatantMode.h"
#include "../../../../../includes/module/impl/combat/autorefill/mode/AutoRefillLegitMode.h"
#include "../../../../../includes/module/impl/combat/autorefill/mode/AutoRefillSemiBlatantMode.h"
#include "hook/sub/GetSlotAtPositionHook.h"
#include "wrapper/minecraft/world/WorldSettingsGameType.h"
#include "module/impl/visual/NotificationModule.h"
#include "util/Debug.h"
#include <string>

#ifdef WHIP_DEV_MODE
namespace {
    // Read-only: returns the fully-qualified Java class name of a jobject.
    // Used purely for diagnostics (Feather custom-inventory investigation).
    std::string jniClassName(JNIEnv* env, jobject obj) {
        if (!env || !obj) return "<null>";
        jclass cls = env->GetObjectClass(obj);
        if (!cls) { env->ExceptionClear(); return "<no-class>"; }
        jclass classClass = env->FindClass("java/lang/Class");
        if (!classClass) { env->ExceptionClear(); env->DeleteLocalRef(cls); return "<no-Class>"; }
        jmethodID getName = env->GetMethodID(classClass, "getName", "()Ljava/lang/String;");
        env->DeleteLocalRef(classClass);
        if (!getName) { env->ExceptionClear(); env->DeleteLocalRef(cls); return "<no-getName>"; }
        jstring name = static_cast<jstring>(env->CallObjectMethod(cls, getName));
        env->DeleteLocalRef(cls);
        if (!name || env->ExceptionCheck()) { env->ExceptionClear(); return "<name-failed>"; }
        const char* chars = env->GetStringUTFChars(name, nullptr);
        std::string result = chars ? chars : "<empty>";
        if (chars) env->ReleaseStringUTFChars(name, chars);
        env->DeleteLocalRef(name);
        return result;
    }
}
#endif

void AutoRefillModule::onUpdate(JniScope& scope) {
    Minecraft theMc = Minecraft::getMinecraft(scope.getEnv());
    if (theMc.isNull()) return;

    if (!theMc.inGameHasFocus()) return;

    World theWorld = theMc.theWorld();
    if (theWorld.isNull()) return;

    EntityClientPlayerMP thePlayer = theMc.thePlayer();
    if (thePlayer.isNull()) return;

    InventoryPlayer inventoryPlayer = thePlayer.inventoryPlayer();
    if (inventoryPlayer.isHotbarFull()) return;

    PlayerControllerMP playerController = theMc.playerController();
    if (playerController.isNull()) return;

    WorldSettingsGameType gameType = playerController.currentGameType();
    if (!gameType.isNull()) {
        bool creative = gameType.isCreative();
        if (scope.getEnv()->ExceptionCheck()) {
            scope.getEnv()->ExceptionClear();
        } else if (creative) {
            return;
        }
    }

    GameSettings gameSettings = theMc.gameSettings();
    if (gameSettings.isNull()) return;

    if (randomMode && lastSlotIndex == 0) {
        lastSlotIndex = -1;
    }

    if (const int slot = this->findSlot(inventoryPlayer); slot == -1) return;
    else DEBUG_LOG("[AutoRefill] trigger: found potion slot=%d itemMode=%d mode=%d", slot, this->itemMode, this->mode);

    NotificationModule::addCustomNotification(std::string(getDisplayName()) + " used", ImColor(24, 155, 222));

    KeyBinding keyBindInventory = gameSettings.keyBindInventory();
    if (keyBindInventory.isNull()) return;

    KeyBinding keyBindForward = gameSettings.keyBindForward();
    if (keyBindForward.isNull()) return;

    isForwarding = keyBindForward.pressed();
    refilling_ = true;

    keyBindInventory.setPressTime(1);

    constexpr int MAX_SCREEN_WAIT_MS = 1000;
    constexpr int SCREEN_CHECK_INTERVAL_MS = 20;
    constexpr int MAX_SCREEN_ITERATIONS = MAX_SCREEN_WAIT_MS / SCREEN_CHECK_INTERVAL_MS;

    GuiScreen currentScreen;
    int screenWaitAttempts = 0;

    do {
        if (keyBindInventory.getPressTime() == 0) {
            keyBindInventory.setPressTime(1);
        }
        Sleep(SCREEN_CHECK_INTERVAL_MS);
        currentScreen = theMc.currentScreen();

        if (++screenWaitAttempts >= MAX_SCREEN_ITERATIONS) {
            DEBUG_LOG("[AutoRefill] TIMEOUT: currentScreen stayed null after %d attempts (~%dms). "
                      "pressTime mechanism did NOT open a vanilla screen -> refilling_ LEFT TRUE (clicks now blocked).",
                      screenWaitAttempts, MAX_SCREEN_WAIT_MS);
            keyBindForward.pressed(isForwarding);
            return;
        }
    } while (currentScreen.isNull());

    DEBUG_LOG("[AutoRefill] screen opened after %d attempts (~%dms). currentScreen class = %s",
              screenWaitAttempts, screenWaitAttempts * SCREEN_CHECK_INTERVAL_MS,
              jniClassName(scope.getEnv(), currentScreen.getObj()).c_str());

    Container openContainer = thePlayer.openContainer();
    DEBUG_LOG("[AutoRefill] openContainer: isNull=%d class=%s windowId=%d",
              openContainer.isNull() ? 1 : 0,
              openContainer.isNull() ? "<null>" : jniClassName(scope.getEnv(), openContainer.getObj()).c_str(),
              openContainer.isNull() ? -1 : openContainer.windowId());
    if (openContainer.isNull()) {
        refilling_ = false;
        thePlayer.closeScreen();
        keyBindForward.pressed(isForwarding);
        return;
    }

    this->refillMode->onEnable();

    const int reelSpeed = 10 - speed;
    if (refillMode->isInstant()) {

        constexpr int MAX_ITER = 100;
        int iter = 0;

        while (!inventoryPlayer.isHotbarFull() && iter++ < MAX_ITER) {
            if (theMc.currentScreen().isNull()) break;

            int slot = findSlot(inventoryPlayer);
            if (slot == -1) break;

            int distance = lastSlotIndex == -1 ? 0 :
                calculateSlotDistance(lastSlotIndex, slot);

            refillMode->handleClick(
                slot, reelSpeed, distance,
                openContainer, thePlayer, theMc,
                dynamicSpeed, transition
            );

            lastSlotIndex = slot;
        }
    } else {
        plannedSlots.clear();
        lastSlotIndex = -1;

        const int emptySlots = inventoryPlayer.countEmptyHotbarSlots();
        std::vector<std::pair<int, int>> slotsToClick;
        for (int i = 0; i < emptySlots; i++) {
            const int currentSlot = this->findSlot(inventoryPlayer);
            if (currentSlot == -1) break;

            int distance = 0;
            if (lastSlotIndex != -1) {
                distance = calculateSlotDistance(lastSlotIndex, currentSlot);
            }

            plannedSlots.insert(currentSlot);
            slotsToClick.emplace_back(currentSlot, distance);
            lastSlotIndex = currentSlot;
        }

        DEBUG_LOG("[AutoRefill] enqueue %zu click(s), emptyHotbarSlots=%d, windowId=%d, reelSpeed=%d",
                  slotsToClick.size(), emptySlots, openContainer.windowId(), reelSpeed);
        for (const auto& [slot, distance] : slotsToClick) {
            if (theMc.currentScreen().isNull()) {
                DEBUG_LOG("[AutoRefill] abort enqueue loop: currentScreen became null mid-loop");
                break;
            }
            DEBUG_LOG("[AutoRefill] enqueue click slot=%d distance=%d", slot, distance);
            this->refillMode->handleClick(slot, reelSpeed, distance, openContainer, thePlayer, theMc, this->dynamicSpeed, this->transition);
        }

        plannedSlots.clear();
        lastSlotIndex = -1;
        AutoRefillSemiBlatantMode::flushBatch();
    }

    refillMode->onDisable();
    Sleep(50);
    GuiScreen screenAfter = theMc.currentScreen();
    if (!screenAfter.isNull()) {
        thePlayer.closeScreen();
    }
    keyBindForward.pressed(isForwarding);
    refilling_ = false;
    waitingForRefill = false;
    closing = false;
}

void AutoRefillModule::onTick(const OnRunTickEvent& event) {
    AutoRefillLegitMode::notifyTick();
    AutoRefillSemiBlatantMode::onTick(event.getEnv());
}

void AutoRefillModule::onPostLivingUpdate(const ItemUseEvent& event) {
    AutoRefillSemiBlatantMode::onPostLivingUpdate(event.getEnv());
}

std::unique_ptr<AutoRefillMode> AutoRefillModule::createMode(Mode mode) {
    if (mode == Mode::BLATANT)
        return std::make_unique<AutoRefillBlatantMode>();
    if (mode == Mode::SEMI_BLATANT)
        return std::make_unique<AutoRefillSemiBlatantMode>();
    return std::make_unique<AutoRefillLegitMode>();
}

void AutoRefillModule::initializeSlotPatterns() {
   patterns.push_back(std::vector<int>());
    for (int i = 9; i < 36; i++) {
        patterns.back().push_back(i);
    }

    patterns.push_back(std::vector<int>());
    for (int i = 35; i >= 9; i--) {
        patterns.back().push_back(i);
    }

    patterns.push_back(std::vector<int>());
    for (int col = 0; col < 9; col++) {
        if (col % 2 == 0) {
            for (int row = 0; row < 3; row++) {
                patterns.back().push_back(9 + row * 9 + col);
            }
        }
        else {
            for (int row = 2; row >= 0; row--) {
                patterns.back().push_back(9 + row * 9 + col);
            }
        }
    }
}

int AutoRefillModule::findSlot(InventoryPlayer& inventoryPlayer) {
    if (!randomMode) {
        for (int i = 9; i < 36; i++) {

            if (plannedSlots.contains(i))
                continue;

           ItemStack currentItemStack = inventoryPlayer.getItem(i);
           if (const HealType healType = this->getItemHealType(currentItemStack);
               (this->itemMode == 0 && healType == HealType::Heal) ||
               (this->itemMode == 1 && healType == HealType::Soup) ||
               (this->itemMode == 2 && healType != HealType::None))

                return i;
        }
    }
    else {
        if (lastSlotIndex == -1) {
            static std::mt19937 gen(std::chrono::steady_clock::now().time_since_epoch().count());

            std::uniform_int_distribution<> patternDist(0, patterns.size() - 1);
            currentPatternIndex = patternDist(gen);

            if (const std::vector<int>& currentPattern = patterns[currentPatternIndex]; !currentPattern.empty()) {
                std::uniform_int_distribution<> startDist(0, currentPattern.size() - 1);
                const int randomStartIndex = startDist(gen);
                lastSlotIndex = currentPattern[randomStartIndex];
                lastIndex = randomStartIndex;

                if (std::uniform_int_distribution extraRandomDist(1, 100); extraRandomDist(gen) <= 30) {
                    currentPatternIndex = (currentPatternIndex + 1) % patterns.size();
                }
            }
        }

        const int startPatternIndex = currentPatternIndex;
        const int startLastIndex = lastIndex;

        bool firstTry = true;
        do {
            const std::vector<int>& currentPattern = patterns[currentPatternIndex];

            std::vector<std::pair<int, int>> validSlotsWithDistance;

            for (int i = 0; i < currentPattern.size(); i++) {
                int index = (lastIndex + i) % currentPattern.size();
                int slot = currentPattern[index];
                if (plannedSlots.contains(slot))
                    continue;

                auto currentItemStack = inventoryPlayer.getItem(slot);

                if (const HealType healType = this->getItemHealType(currentItemStack);
                    (this->itemMode == 0 && healType == HealType::Heal) ||
                    (this->itemMode == 1 && healType == HealType::Soup) ||
                    (this->itemMode == 2 && healType != HealType::None)) {

                    int distance = calculateSlotDistance(lastSlotIndex, slot);
                    validSlotsWithDistance.emplace_back(index, distance);
                }
            }

            if (!validSlotsWithDistance.empty()) {
                std::ranges::sort(validSlotsWithDistance,
                             [](const std::pair<int, int>& a, const std::pair<int, int>& b) {
                                 return a.second < b.second;
                             });

                int selectedIndex = validSlotsWithDistance[0].first;
                const int selectedSlot = currentPattern[selectedIndex];

                lastIndex = (selectedIndex + 1) % currentPattern.size();
                lastSlotIndex = selectedSlot;

                return selectedSlot;
            }

            currentPatternIndex = (currentPatternIndex + 1) % patterns.size();
            if (firstTry) {
                firstTry = false;
            }
            else if (currentPatternIndex == startPatternIndex) {
                break;
            }

        } while (true);

        currentPatternIndex = startPatternIndex;
        lastIndex = startLastIndex;
    }
    return -1;
}

int AutoRefillModule::calculateSlotDistance(const int& slot1, const int& slot2) {
    int row1 = (slot1 - 9) / 9;
    int col1 = (slot1 - 9) % 9;
    int row2 = (slot2 - 9) / 9;
    int col2 = (slot2 - 9) % 9;

    return abs(row1 - row2) + abs(col1 - col2);
}

AutoRefillModule::HealType AutoRefillModule::getItemHealType(ItemStack& itemStack) {
    if (itemStack.isNull()) return HealType::None;

    int damage = itemStack.metadata();
    if (damage == 16421 || damage == 16453) return HealType::Heal;
    if (itemStack.isSoup()) return HealType::Soup;

    return HealType::None;
}

REGISTER_MODULE(AutoRefillModule, ModuleType::AUTO_REFILL)
