#ifndef IBLOCKSTATE_H_
#define IBLOCKSTATE_H_

#include "../../../../../includes/wrapper/primitive/JavaObject.h"
#include "../block.h"

class IBlockState : public JavaObject {
private:
    static jmethodID getBlockId;

public:
    IBlockState(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    Block getBlock() {
        if (!getBlockId) getBlockId = mappings->getMethod("IBlockState#getBlock");

        jobject obj = this->env->CallObjectMethod(this->obj, getBlockId);
        if (!obj) return Block(NULL, NULL);

        return Block(this->env, obj);
    }
};

#endif
