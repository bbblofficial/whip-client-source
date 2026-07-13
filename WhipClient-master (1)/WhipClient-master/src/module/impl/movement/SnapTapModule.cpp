#include "../../../../includes/module/impl/movement/SnapTapModule.h"
#include "bus/EventBus.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/settings/GameSettings.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"

void SnapTapModule::registerEvents() {
    subscribe<OnRunTickEvent>([this](const OnRunTickEvent& event) {
        onTick(event);
    }, EventPriority::HIGH);
}

bool SnapTapModule::isPhysDown(JNIEnv* env, int keyCode) {
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

void SnapTapModule::onTick(const OnRunTickEvent& event) {
    if (!this->isEnabled()) return;

    JNIEnv* env = event.getEnv();
    if (!env) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    EntityClientPlayerMP player = mc.thePlayer();
    if (player.isNull()) return;

    if (onlyOnGround && !player.onGround()) return;
    if (disableOnSneak && player.isSneaking()) return;

    GameSettings gs = mc.gameSettings();
    if (gs.isNull()) return;

    KeyBinding kLeft    = gs.keyBindLeft();
    KeyBinding kRight   = gs.keyBindRight();
    KeyBinding kForward = gs.keyBindForward();
    KeyBinding kBack    = gs.keyBindBack();

    if (kLeft.isNull() || kRight.isNull() || kForward.isNull() || kBack.isNull()) return;

    bool physLeft    = isPhysDown(env, kLeft.keyCode());
    bool physRight   = isPhysDown(env, kRight.keyCode());
    bool physForward = isPhysDown(env, kForward.keyCode());
    bool physBack    = isPhysDown(env, kBack.keyCode());

    if (axis != 2 && physLeft && physRight) {
        bool newLeft  = physLeft  && !prevLeft_;
        bool newRight = physRight && !prevRight_;

        if (newRight && !newLeft) {
            kLeft.pressed(false);  suppLeft_  = true;
            if (suppRight_) { kRight.pressed(true); suppRight_ = false; }
        } else if (newLeft && !newRight) {
            kRight.pressed(false); suppRight_ = true;
            if (suppLeft_)  { kLeft.pressed(true);  suppLeft_  = false; }
        }
    } else if (physLeft) {
        if (suppLeft_)  { kLeft.pressed(true);  suppLeft_  = false; }
        suppRight_ = false;
    } else if (physRight) {
        if (suppRight_) { kRight.pressed(true); suppRight_ = false; }
        suppLeft_ = false;
    } else {
        suppLeft_ = suppRight_ = false;
    }

    if (axis != 1 && physForward && physBack) {
        bool newForward = physForward && !prevForward_;
        bool newBack    = physBack    && !prevBack_;

        if (newBack && !newForward) {
            kForward.pressed(false); suppForward_ = true;
            if (suppBack_)    { kBack.pressed(true);    suppBack_    = false; }
        } else if (newForward && !newBack) {
            kBack.pressed(false);    suppBack_    = true;
            if (suppForward_) { kForward.pressed(true); suppForward_ = false; }
        }
    } else if (physForward) {
        if (suppForward_) { kForward.pressed(true); suppForward_ = false; }
        suppBack_ = false;
    } else if (physBack) {
        if (suppBack_)    { kBack.pressed(true);    suppBack_    = false; }
        suppForward_ = false;
    } else {
        suppForward_ = suppBack_ = false;
    }

    prevLeft_    = physLeft;
    prevRight_   = physRight;
    prevForward_ = physForward;
    prevBack_    = physBack;
}

REGISTER_MODULE(SnapTapModule, ModuleType::SNAP_TAP)
