#include "../../../../includes/module/impl/misc/ChestStealerModule.h"
#include "wrapper/minecraft/client/minecraft.h"
#include "wrapper/minecraft/inventory/Slot.h"
#include "wrapper/minecraft/item/ItemStack.h"
#include "wrapper/minecraft/util/BlockPos.h"
#include "wrapper/minecraft/block/state/IBlockstate.h"
#include "wrapper/minecraft/block/Block.h"
#include "handler/ModuleHandler.h"
#include "hook/sub/GetSlotAtPositionHook.h"
#include <windows.h>
#include <cmath>
#include <vector>

std::random_device ChestStealerModule::rd_;
std::mt19937 ChestStealerModule::gen_(rd_());

ChestStealerModule::ChestStealerModule()
    : DedicatedThreadBaseModule(BindType::TOGGLE, 0, 30) {}

void ChestStealerModule::onLoad() {
    DedicatedThreadBaseModule::onLoad();

    COMBO_SETTING(mode, "Blatant", "Legit");
    INT_SLIDER(speed, 5, 1, 10);
    BOOL_SETTING_CONDITIONAL(autoOpen, false);
    BOOL_SETTING_CONDITIONAL(closeAfterSteal, true);
}

void ChestStealerModule::onEnable() {
    DedicatedThreadBaseModule::onEnable();
    stealing_ = false;
    closing_ = false;
    blatantActive_ = false;
    blatantSlotIndex_ = 0;
    blatantChestSlotCount_ = 0;
    blatantTickDelay_ = 0;
}

void ChestStealerModule::onDisable() {
    keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
    stealing_ = false;
    closing_ = false;
    blatantActive_ = false;
    blatantSlotIndex_ = 0;
    blatantTickDelay_ = 0;
    stopDedicatedThread();
}

void ChestStealerModule::onPacketSend(const AddSendQueueEvent& event) {
    if (!this->enable) return;
    if (!blatantActive_) return;
    if (ourClick_) return;

    JNIEnv* env = event.getEnv();
    if (!env) return;

    jobject packet = event.getPacketObject();
    if (!packet) return;

    const char* name = event.getPacketName();
    if (name && strstr(name, "ClickWindow")) {
        const_cast<AddSendQueueEvent&>(event).setCancelled(true);
    }
}

void ChestStealerModule::onUpdate(JniScope& scope) {
    JNIEnv* env = scope.getEnv();

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    WorldClient theWorld = mc.theWorld();
    if (theWorld.isNull()) return;

    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) return;

    auto isChestOpen = [&]() -> bool {
        GuiScreen screen = mc.currentScreen();
        if (screen.isNull()) return false;
        screen.setDeleteRef(false);
        return screen.isChest();
    };

    if (!isChestOpen() && autoOpen) {
        MovingObjectPosition mop = mc.objectMouseOver();
        if (!mop.isNull() && mop.typeOfHit() == MovingObjectPosition::TypeOfHit::BLOCK) {
            bool isLookingAtChest = false;
            env->PushLocalFrame(8);
            auto pos = mop.getPosition();
            Block block = theWorld.getBlockAt(pos.x, pos.y, pos.z);
            if (!block.isNull()) {
                jstring name = block.getUnlocalizedName();
                if (name) {
                    const char* c = env->GetStringUTFChars(name, nullptr);
                    if (c) {
                        isLookingAtChest = (strstr(c, "chest") != nullptr);
                        env->ReleaseStringUTFChars(name, c);
                    }
                }
            }
            env->PopLocalFrame(nullptr);

            if (isLookingAtChest) {
                GameSettings settings = mc.gameSettings();
                if (!settings.isNull()) {
                    KeyBinding useItem = settings.keyBindUseItem();
                    if (!useItem.isNull()) {
                        useItem.setPressTime(1);
                    }
                }

                constexpr int MAX_WAIT_MS = 500;
                constexpr int CHECK_INTERVAL_MS = 25;
                int waited = 0;

                while (waited < MAX_WAIT_MS) {
                    Sleep(CHECK_INTERVAL_MS);
                    waited += CHECK_INTERVAL_MS;
                    if (isChestOpen()) break;
                }
            }
        }
    }

    if (!isChestOpen()) return;

    Container container = thePlayer.openContainer();
    if (container.isNull()) return;

    ArrayList slots = container.inventorySlots();
    if (slots.isNull()) return;

    int totalSlots = slots.size();
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
    int chestSlotCount = totalSlots - 36;
    if (chestSlotCount <= 0) return;

    PlayerControllerMP playerController = mc.playerController();
    if (playerController.isNull()) return;

    if (mode == 0) {
        if (!blatantActive_) {
            blatantSlotIndex_ = 0;
            blatantChestSlotCount_ = chestSlotCount;
            blatantTickDelay_ = 1;
            blatantActive_ = true;
        }
        return;
    }

    stealing_ = true;
    stealLegit(env, container, thePlayer, mc, chestSlotCount);
    stealing_ = false;

    if (closeAfterSteal) {
        bool hasItemsLeft = false;
        for (int i = 0; i < chestSlotCount && i < slots.size(); i++) {
            JavaObject slotJO = slots.get(i);
            if (!slotJO.isNull()) {
                slotJO.setDeleteRef(false);
                Slot slot(env, slotJO.getObj());
                ItemStack stack = slot.getStack();
                if (!stack.isNull()) {
                    hasItemsLeft = true;
                    break;
                }
            }
        }

        if (!hasItemsLeft) {
            closing_ = true;
        }
    }
}

void ChestStealerModule::calcGuiLayout(Minecraft& mc, int chestSlotCount,
                                        int& guiLeft, int& guiTop, double& scaleX, double& scaleY,
                                        POINT& clientOrigin) {
    int displayWidth = mc.displayWidth();
    int displayHeight = mc.displayHeight();
    bool isUnicode = mc.isUnicode();
    GameSettings gameSettings = mc.gameSettings();
    int guiScale = gameSettings.guiScale();

    int scaleFactor = 1;
    int scaleLimit = guiScale == 0 ? 1000 : guiScale;
    while (scaleFactor < scaleLimit &&
           displayWidth / (scaleFactor + 1) >= 320 &&
           displayHeight / (scaleFactor + 1) >= 240) {
        ++scaleFactor;
    }
    if (isUnicode && scaleFactor % 2 != 0 && scaleFactor != 1) --scaleFactor;

    int scaledW = (displayWidth + scaleFactor - 1) / scaleFactor;
    int scaledH = (displayHeight + scaleFactor - 1) / scaleFactor;

    constexpr int GUI_WIDTH = 176;
    int guiHeight = getChestGuiHeight(chestSlotCount);
    guiLeft = (scaledW - GUI_WIDTH) / 2;
    guiTop = (scaledH - guiHeight) / 2;
    scaleX = static_cast<double>(displayWidth) / static_cast<double>(scaledW);
    scaleY = static_cast<double>(displayHeight) / static_cast<double>(scaledH);

    HWND mcWindow = FindWindowA("LWJGL", nullptr);
    if (!mcWindow) mcWindow = FindWindowA("GLFW30", nullptr);
    if (!mcWindow) mcWindow = FindWindowA(nullptr, "Lunar Client");

    clientOrigin = {0, 0};
    if (mcWindow) ClientToScreen(mcWindow, &clientOrigin);
}

void ChestStealerModule::getSlotScreenPos(int slotIndex, int guiLeft, int guiTop,
                                           double scaleX, double scaleY, const POINT& clientOrigin,
                                           int& outX, int& outY) {
    int col = slotIndex % 9;
    int row = slotIndex / 9;
    int slotGuiX = guiLeft + 8 + col * 18 + 8;
    int slotGuiY = guiTop + 18 + row * 18 + 8;
    outX = clientOrigin.x + static_cast<int>(slotGuiX * scaleX);
    outY = clientOrigin.y + static_cast<int>(slotGuiY * scaleY);
}

void ChestStealerModule::tickBlatant(JNIEnv* env) {
    if (!blatantActive_) return;

    if (blatantTickDelay_ > 0) {
        blatantTickDelay_--;
        return;
    }

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) { blatantActive_ = false; return; }

    GuiScreen screen = mc.currentScreen();
    if (screen.isNull()) { blatantActive_ = false; return; }
    screen.setDeleteRef(false);
    if (!screen.isChest()) { blatantActive_ = false; return; }

    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) { blatantActive_ = false; return; }

    Container container = thePlayer.openContainer();
    if (container.isNull()) { blatantActive_ = false; return; }

    PlayerControllerMP playerController = mc.playerController();
    if (playerController.isNull()) { blatantActive_ = false; return; }

    ArrayList slotsList = container.inventorySlots();
    if (slotsList.isNull()) { blatantActive_ = false; return; }

    int windowId = container.windowId();
    int itemsPerTick = speed;
    int tickDelayBetween = (speed < 5) ? (3 - speed / 2) : 0;

    int stolen = 0;
    while (blatantSlotIndex_ < blatantChestSlotCount_ && stolen < itemsPerTick) {
        if (blatantSlotIndex_ < slotsList.size()) {
            JavaObject slotJO = slotsList.get(blatantSlotIndex_);
            if (!slotJO.isNull()) {
                slotJO.setDeleteRef(false);
                Slot slot(env, slotJO.getObj());
                ItemStack stack = slot.getStack();
                if (!stack.isNull()) {
                    {
                        std::lock_guard<std::mutex> lock(GetSlotAtPositionHook::slotsMutex);
                        GetSlotAtPositionHook::spoofedSlots.push(blatantSlotIndex_);
                        GetSlotAtPositionHook::spoofedSlots.push(blatantSlotIndex_);
                        GetSlotAtPositionHook::spoofedSlots.push(blatantSlotIndex_);
                        GetSlotAtPositionHook::spoofActive = true;
                    }

                    ourClick_ = true;
                    playerController.windowClick(windowId, blatantSlotIndex_, 0, 1, thePlayer);
                    ourClick_ = false;
                    stolen++;
                }
            }
        }
        blatantSlotIndex_++;
    }

    {
        std::lock_guard lock(GetSlotAtPositionHook::slotsMutex);
        while (!GetSlotAtPositionHook::spoofedSlots.empty()) {
            GetSlotAtPositionHook::spoofedSlots.pop();
        }
        GetSlotAtPositionHook::spoofActive = false;
    }

    if (stolen > 0) {
        blatantTickDelay_ = tickDelayBetween;
    }

    if (blatantSlotIndex_ >= blatantChestSlotCount_) {
        blatantActive_ = false;
        stealing_ = false;

        if (closeAfterSteal) {
            bool hasItemsLeft = false;
            for (int i = 0; i < blatantChestSlotCount_ && i < slotsList.size(); i++) {
                JavaObject slotJO = slotsList.get(i);
                if (!slotJO.isNull()) {
                    slotJO.setDeleteRef(false);
                    Slot slot(env, slotJO.getObj());
                    ItemStack stack = slot.getStack();
                    if (!stack.isNull()) {
                        hasItemsLeft = true;
                        break;
                    }
                }
            }
            if (!hasItemsLeft) {
                closing_ = true;
            }
        }
    }
}

void ChestStealerModule::stealLegit(JNIEnv* env, Container& container, EntityClientPlayerMP& player,
                                     Minecraft& mc, int chestSlotCount) {
    int guiLeft, guiTop;
    double scaleX, scaleY;
    POINT clientOrigin;
    calcGuiLayout(mc, chestSlotCount, guiLeft, guiTop, scaleX, scaleY, clientOrigin);

    ArrayList slotsList = container.inventorySlots();
    std::vector<bool> slotHasItem(chestSlotCount, false);

    if (!slotsList.isNull()) {
        for (int i = 0; i < chestSlotCount && i < slotsList.size(); i++) {
            JavaObject slotJO = slotsList.get(i);
            if (!slotJO.isNull()) {
                slotJO.setDeleteRef(false);
                Slot slot(env, slotJO.getObj());
                ItemStack stack = slot.getStack();
                if (!stack.isNull()) {
                    slotHasItem[i] = true;
                }
            }
        }
    }

    bool useMouseMove = getInternalSpeed() < 30;
    int delayMs = std::max(0, 120 - (getInternalSpeed() * 5));

    POINT savedCursorPos;
    GetCursorPos(&savedCursorPos);

    for (int slotIndex = 0; slotIndex < chestSlotCount; slotIndex++) {
        if (!slotHasItem[slotIndex]) continue;

        GuiScreen checkScreen = mc.currentScreen();
        if (checkScreen.isNull()) break;
        checkScreen.setDeleteRef(false);
        if (!checkScreen.isChest()) break;

        int sx, sy;
        getSlotScreenPos(slotIndex, guiLeft, guiTop, scaleX, scaleY, clientOrigin, sx, sy);

        if (getInternalSpeed() < 20) {
            std::uniform_int_distribution<int> offsetDist(-3, 3);
            sx += offsetDist(gen_);
            sy += offsetDist(gen_);
        }

        if (useMouseMove) {
            smoothMouseMove(sx, sy);
        } else {
            SetCursorPos(sx, sy);
        }

        keybd_event(VK_SHIFT, 0, 0, 0);
        Sleep(5);
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
        int holdMs = std::max(20, 30 - getInternalSpeed());
        Sleep(holdMs);
        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
        Sleep(5);
        keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);

        if (delayMs > 0) {
            std::uniform_int_distribution<int> jitter(-2, 3);
            int delay = delayMs + jitter(gen_);
            if (delay > 0) Sleep(delay);
        }
    }

    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
    SetCursorPos(savedCursorPos.x, savedCursorPos.y);
}

void ChestStealerModule::smoothMouseMove(int targetX, int targetY) {
    POINT cur;
    GetCursorPos(&cur);

    int dx = targetX - cur.x;
    int dy = targetY - cur.y;
    double dist = sqrt(dx * dx + dy * dy);

    if (dist < 5) {
        SetCursorPos(targetX, targetY);
        return;
    }

    int steps = std::clamp(static_cast<int>(dist / 8), 4, 15);

    for (int i = 1; i <= steps; i++) {
        float t = static_cast<float>(i) / static_cast<float>(steps);
        float ease = t * t * (3.0f - 2.0f * t);

        int x = cur.x + static_cast<int>(dx * ease);
        int y = cur.y + static_cast<int>(dy * ease);

        if (i < steps) {
            std::uniform_int_distribution<int> jit(-1, 1);
            x += jit(gen_);
            y += jit(gen_);
        }

        SetCursorPos(x, y);
        Sleep(2 + (i % 2));
    }

    SetCursorPos(targetX, targetY);
}

int ChestStealerModule::getChestGuiHeight(int chestSlotCount) {
    int rows = chestSlotCount / 9;
    return 114 + rows * 18;
}

void ChestStealerModule::onTick(const OnRunTickEvent& event) {
    if (!this->isEnabled()) return;
    if (blatantActive_) {
        tickBlatant(event.getEnv());
    }

    if (!closing_) return;

    Minecraft mc = Minecraft::getMinecraft(event.getEnv());
    if (mc.isNull()) return;

    EntityClientPlayerMP thePlayer = mc.thePlayer();
    if (thePlayer.isNull()) return;

    GuiScreen screen = mc.currentScreen();
    if (!screen.isNull()) {
        screen.setDeleteRef(false);
        if (screen.isChest()) {
            thePlayer.closeScreen();
        }
    }

    closing_ = false;
}

REGISTER_MODULE(ChestStealerModule, ModuleType::CHEST_STEALER)
