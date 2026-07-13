#ifndef BLOCK_H_
#define BLOCK_H_

#include "../../../../includes/wrapper/primitive/JavaObject.h"

class World;
class AxisAlignedBB;

class Block : public JavaObject {
private:

    static jmethodID getUnlocalizedNameId;
    static jmethodID getCollisionBoundingBoxFromPoolId;

public:
    Block(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    jstring getUnlocalizedName() {
        if (!getUnlocalizedNameId) getUnlocalizedNameId = mappings->getMethod("Block#getUnlocalizedName");

        return (jstring) this->env->CallObjectMethod(this->obj, getUnlocalizedNameId);
    }

    AxisAlignedBB getCollisionBoundingBoxFromPool(World world, int x, int y, int z);

};

#endif
