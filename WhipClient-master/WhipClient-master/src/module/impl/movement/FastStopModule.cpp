#include "../../../../includes/module/impl/movement/FastStopModule.h"
#include "bus/EventBus.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/settings/GameSettings.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "../../../../includes/handler/ProviderHandler.h"
#include "../../../../includes/provider/impl/GameStateProvider.h"

void FastStopModule::registerEvents() {
    subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
        onTick(event);
    }, EventPriority::MEDIUM);
}

bool FastStopModule::isPhysDown(JNIEnv* env, int keyCode) {
    if (keyCode <= 0) return false;

    if (!lwjglKeyboardClass_) {
        jclass threadClass = env->FindClass("java/lang/Thread");
        if (!threadClass) { env->ExceptionClear(); return false; }
        jmethodID currentThread = env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
        if (!currentThread) { env->ExceptionClear(); env->DeleteLocalRef(threadClass); return false; }
        jobject thread = env->CallStaticObjectMethod(threadClass, currentThread);
        if (!thread) { env->ExceptionClear(); env->DeleteLocalRef(threadClass); return false; }
        jmethodID getCtxCl = env->GetMethodID(threadClass, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
        env->DeleteLocalRef(threadClass);
        if (!getCtxCl) { env->ExceptionClear(); env->DeleteLocalRef(thread); return false; }
        jobject classLoader = env->CallObjectMethod(thread, getCtxCl);
        env->DeleteLocalRef(thread);
        if (!classLoader) { env->ExceptionClear(); return false; }

        jclass clClass = env->FindClass("java/lang/ClassLoader");
        if (!clClass) { env->ExceptionClear(); env->DeleteLocalRef(classLoader); return false; }
        jmethodID loadClass = env->GetMethodID(clClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        env->DeleteLocalRef(clClass);
        if (!loadClass) { env->ExceptionClear(); env->DeleteLocalRef(classLoader); return false; }

        jstring clsName = env->NewStringUTF("org.lwjgl.input.Keyboard");
        jobject cls = env->CallObjectMethod(classLoader, loadClass, clsName);
        env->DeleteLocalRef(clsName);
        env->DeleteLocalRef(classLoader);
        if (!cls || env->ExceptionCheck()) { env->ExceptionClear(); return false; }

        lwjglKeyboardClass_ = static_cast<jclass>(env->NewGlobalRef(cls));
        env->DeleteLocalRef(cls);
    }
    if (!isKeyDownMethodId_) {
        isKeyDownMethodId_ = env->GetStaticMethodID(lwjglKeyboardClass_, "isKeyDown", "(I)Z");
        if (!isKeyDownMethodId_) { env->ExceptionClear(); return false; }
    }

    jboolean result = env->CallStaticBooleanMethod(lwjglKeyboardClass_, isKeyDownMethodId_, keyCode);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    return result;
}

void FastStopModule::onTick(const OnRunTickEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    if (!this->isEnabled() && !csActiveF_ && !csActiveB_ && !csActiveL_ && !csActiveR_) {
        prevForward_ = prevBack_ = prevLeft_ = prevRight_ = false;
        return;
    }

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    GameSettings gs = mc.gameSettings();
    if (gs.isNull()) return;

    KeyBinding kForward = gs.keyBindForward();
    KeyBinding kBack    = gs.keyBindBack();
    KeyBinding kLeft    = gs.keyBindLeft();
    KeyBinding kRight   = gs.keyBindRight();
    if (kForward.isNull() || kBack.isNull() || kLeft.isNull() || kRight.isNull()) return;

    bool physForward = isPhysDown(env, kForward.keyCode());
    bool physBack    = isPhysDown(env, kBack.keyCode());
    bool physLeft    = isPhysDown(env, kLeft.keyCode());
    bool physRight   = isPhysDown(env, kRight.keyCode());

    if (csActiveF_) { kBack.pressed(physBack);    csActiveF_ = false; }
    if (csActiveB_) { kForward.pressed(physForward); csActiveB_ = false; }
    if (csActiveL_) { kRight.pressed(physRight);  csActiveL_ = false; }
    if (csActiveR_) { kLeft.pressed(physLeft);    csActiveR_ = false; }

    EntityClientPlayerMP player = mc.thePlayer();
    bool canApply = this->isEnabled() && !player.isNull();
    if (canApply && disableOnSneak && player.isSneaking()) canApply = false;
    if (canApply && player.isInWater())                    canApply = false;

    if (canApply) {
        auto* gameState = ProviderHandler::getInstance()
            .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
        if (gameState && (!gameState->inGameHasFocus()
                          || gameState->isInventoryOpen()
                          || gameState->isChestOpen())) {
            canApply = false;
        }
    }

    if (canApply) {

        constexpr int MIN_HOLD_TICKS = 2;

        if (axis != 1) {
            if (prevForward_ && !physForward && !physBack && forwardHeldTicks_ >= MIN_HOLD_TICKS) {
                csActiveF_ = true;
                kBack.pressed(true);
                kForward.pressed(false);
            } else if (prevBack_ && !physBack && !physForward && backHeldTicks_ >= MIN_HOLD_TICKS) {
                csActiveB_ = true;
                kForward.pressed(true);
                kBack.pressed(false);
            }
        }

        if (axis != 2) {
            if (prevLeft_ && !physLeft && !physRight && leftHeldTicks_ >= MIN_HOLD_TICKS) {
                csActiveL_ = true;
                kRight.pressed(true);
                kLeft.pressed(false);
            } else if (prevRight_ && !physRight && !physLeft && rightHeldTicks_ >= MIN_HOLD_TICKS) {
                csActiveR_ = true;
                kLeft.pressed(true);
                kRight.pressed(false);
            }
        }

        forwardHeldTicks_ = physForward ? forwardHeldTicks_ + 1 : 0;
        backHeldTicks_    = physBack    ? backHeldTicks_    + 1 : 0;
        leftHeldTicks_    = physLeft    ? leftHeldTicks_    + 1 : 0;
        rightHeldTicks_   = physRight   ? rightHeldTicks_   + 1 : 0;

        prevForward_ = physForward;
        prevBack_    = physBack;
        prevLeft_    = physLeft;
        prevRight_   = physRight;
    } else {

        prevForward_ = prevBack_ = prevLeft_ = prevRight_ = false;
        forwardHeldTicks_ = backHeldTicks_ = leftHeldTicks_ = rightHeldTicks_ = 0;
    }
}

REGISTER_MODULE(FastStopModule, ModuleType::FAST_STOP)
