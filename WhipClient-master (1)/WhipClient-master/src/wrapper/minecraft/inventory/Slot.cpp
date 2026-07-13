#include "../../../../includes/wrapper/minecraft/inventory/Slot.h"
#include "../../../../includes/wrapper/minecraft/item/ItemStack.h"
#include "../../../../includes/handler/MappingHandler.h"

jfieldID Slot::xDisplayPositionId = nullptr;
jfieldID Slot::yDisplayPositionId = nullptr;
jmethodID Slot::stackMethodId = nullptr;

int Slot::xDisplayPosition() {
    if (!xDisplayPositionId) {

        xDisplayPositionId = Mappings::getInstance().getField("Slot#xDisplayPosition");
        if (!xDisplayPositionId) {
            jclass slotClass = env->GetObjectClass(this->obj);
            if (slotClass) {
                xDisplayPositionId = env->GetFieldID(slotClass, "xDisplayPosition", "I");
                if (!xDisplayPositionId) {
                    env->ExceptionClear();
                    xDisplayPositionId = env->GetFieldID(slotClass, "xPos", "I");
                    if (!xDisplayPositionId) env->ExceptionClear();
                }
                env->DeleteLocalRef(slotClass);
            }
        }
    }

    if (!xDisplayPositionId) return 0;
    return env->GetIntField(this->obj, xDisplayPositionId);
}

int Slot::yDisplayPosition() {
    if (!yDisplayPositionId) {
        yDisplayPositionId = Mappings::getInstance().getField("Slot#yDisplayPosition");
        if (!yDisplayPositionId) {
            jclass slotClass = env->GetObjectClass(this->obj);
            if (slotClass) {
                yDisplayPositionId = env->GetFieldID(slotClass, "yDisplayPosition", "I");
                if (!yDisplayPositionId) {
                    env->ExceptionClear();
                    yDisplayPositionId = env->GetFieldID(slotClass, "yPos", "I");
                    if (!yDisplayPositionId) env->ExceptionClear();
                }
                env->DeleteLocalRef(slotClass);
            }
        }
    }

    if (!yDisplayPositionId) return 0;
    return env->GetIntField(this->obj, yDisplayPositionId);
}

ItemStack Slot::getStack() {
    if (!stackMethodId) {
        stackMethodId = Mappings::getInstance().getMethod("Slot#getStack");

        if (!stackMethodId) {
            jclass slotClass = env->GetObjectClass(this->obj);
            if (slotClass) {

                const char* names[] = {"getStack", "func_75211_c", "getItem"};
                for (const char* name : names) {
                    stackMethodId = env->GetMethodID(slotClass, name, "()Lnet/minecraft/item/ItemStack;");
                    if (stackMethodId) break;
                    env->ExceptionClear();
                }

                if (!stackMethodId) {
                    jclass classClass = env->FindClass("java/lang/Class");
                    jclass methodClass = env->FindClass("java/lang/reflect/Method");

                    jclass itemStackClass = mappings ? mappings->getClass("ItemStack") : nullptr;

                    if (classClass && methodClass && itemStackClass) {
                        jmethodID getMethods = env->GetMethodID(classClass, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
                        jmethodID getReturnType = env->GetMethodID(methodClass, "getReturnType", "()Ljava/lang/Class;");
                        jmethodID getParamTypes = env->GetMethodID(methodClass, "getParameterTypes", "()[Ljava/lang/Class;");
                        jmethodID getName = env->GetMethodID(methodClass, "getName", "()Ljava/lang/String;");

                        if (getMethods && getReturnType && getParamTypes && getName) {
                            jobjectArray methods = (jobjectArray)env->CallObjectMethod(slotClass, getMethods);
                            if (methods) {
                                int count = env->GetArrayLength(methods);
                                for (int i = 0; i < count; i++) {
                                    jobject method = env->GetObjectArrayElement(methods, i);
                                    if (!method) continue;

                                    jobject retType = env->CallObjectMethod(method, getReturnType);
                                    jobjectArray params = (jobjectArray)env->CallObjectMethod(method, getParamTypes);

                                    if (retType && params &&
                                        env->GetArrayLength(params) == 0 &&
                                        env->IsSameObject(retType, itemStackClass)) {

                                        jstring jname = (jstring)env->CallObjectMethod(method, getName);
                                        if (jname) {
                                            const char* nameStr = env->GetStringUTFChars(jname, nullptr);
                                            stackMethodId = env->GetMethodID(slotClass, nameStr, "()Lnet/minecraft/item/ItemStack;");
                                            if (env->ExceptionCheck()) env->ExceptionClear();
                                            env->ReleaseStringUTFChars(jname, nameStr);
                                            env->DeleteLocalRef(jname);
                                        }
                                    }

                                    if (retType) env->DeleteLocalRef(retType);
                                    if (params) env->DeleteLocalRef(params);
                                    env->DeleteLocalRef(method);

                                    if (stackMethodId) break;
                                }
                                env->DeleteLocalRef(methods);
                            }
                        }

                        if (methodClass) env->DeleteLocalRef(methodClass);
                        if (classClass) env->DeleteLocalRef(classClass);
                    }
                }
                env->DeleteLocalRef(slotClass);
            }
        }
    }

    if (!stackMethodId) return { env, nullptr };

    jobject stackObj = env->CallObjectMethod(this->obj, stackMethodId);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return { env, nullptr };
    }
    if (!stackObj) {
        return { env, nullptr };
    }
    return { env, stackObj };
}
