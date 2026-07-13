#pragma once

#include "Entity.h"
#include "ai/attributes/IAttribute.h"
#include "ai/attributes/IAttributeInstance.h"
#include "EnumCreatureAttribute.h"
#include "util/Debug.h"
#include "wrapper/minecraft/util/Vec3.h"

class EntityLivingBase : public Entity {
    static jmethodID isOnSameTeamId;
    static jmethodID getHealthId;
    static jfieldID hurtTimeId;
    static jfieldID lastAttackerTimeId;
    static jmethodID setSprintingId;
    static jfieldID isSwingInProgressId;
    static jfieldID swingProgressIntId;
    static jmethodID getArmSwingAnimationEndId;
    static jfieldID SetSwingInProgressId;
    static jmethodID getEntityAttributeId;
    static jmethodID getCreatureAttributeId;
    static jmethodID getLookId;
    static jmethodID setJumpingId;
    static jfieldID isJumpingId;
    static jmethodID canEntityBeSeenId;
    static jfieldID moveStrafingId;
    static jmethodID swingItemId;
    static jmethodID getActivePotionEffectsId;
    static jmethodID getLookIdd;

public:
    EntityLivingBase(JNIEnv* env, jobject obj) : Entity(env, obj) {}

    bool isOnSameTeam(EntityLivingBase entityLivingBase) {
       if (!isOnSameTeamId) isOnSameTeamId = mappings->getMethod("EntityLivingBase#isOnSameTeam");

       return this->env->CallBooleanMethod(this->obj, isOnSameTeamId, entityLivingBase.getObj());
    }

    float getHealth() {
       if (!getHealthId) getHealthId = mappings->getMethod("EntityLivingBase#getHealth");

       return this->env->CallFloatMethod(this->obj, getHealthId);
    }

    int hurtTime() {
       if (!hurtTimeId) hurtTimeId = mappings->getField("EntityLivingBase#hurtTime");

       return this->env->GetIntField(this->obj, hurtTimeId);
    }

    int lastAttackerTime() {
       if (!lastAttackerTimeId) lastAttackerTimeId = mappings->getField("EntityLivingBase#lastAttackerTime");

       return this->env->GetIntField(this->obj, lastAttackerTimeId);
    }

    float renderYawOffset() {
       static jfieldID id = nullptr;
       if (!id) id = mappings->getField("EntityLivingBase#renderYawOffset");
       if (!id) return 0.0f;
       return this->env->GetFloatField(this->obj, id);
    }

    float prevRenderYawOffset() {
       static jfieldID id = nullptr;
       if (!id) id = mappings->getField("EntityLivingBase#prevRenderYawOffset");
       if (!id) return 0.0f;
       return this->env->GetFloatField(this->obj, id);
    }

    float rotationYawHead() {
       static jfieldID id = nullptr;
       if (!id) id = mappings->getField("EntityLivingBase#rotationYawHead");
       if (!id) return 0.0f;
       return this->env->GetFloatField(this->obj, id);
    }

    float limbSwing() {
       static jfieldID id = nullptr;
       if (!id) id = mappings->getField("EntityLivingBase#limbSwing");
       if (!id) return 0.0f;
       return this->env->GetFloatField(this->obj, id);
    }

    float limbSwingAmount() {
       static jfieldID id = nullptr;
       if (!id) id = mappings->getField("EntityLivingBase#limbSwingAmount");
       if (!id) return 0.0f;
       return this->env->GetFloatField(this->obj, id);
    }

    float prevLimbSwingAmount() {
       static jfieldID id = nullptr;
       if (!id) id = mappings->getField("EntityLivingBase#prevLimbSwingAmount");
       if (!id) return 0.0f;
       return this->env->GetFloatField(this->obj, id);
    }

    void setSprinting(bool v) {
       if (!setSprintingId) setSprintingId = mappings->getMethod("EntityLivingBase#setSprinting");

       this->env->CallVoidMethod(this->obj, setSprintingId, v);
    }

   void isJumping(bool val) {
       if (!isJumpingId) {
          isJumpingId = mappings->getField("EntityLivingBase#isJumping");
       }
       this->env->SetBooleanField(this->obj, isJumpingId, val);
    }

    bool isSwingInProgress() {
       if (!isSwingInProgressId) {
          isSwingInProgressId = mappings->getField("EntityLivingBase#isSwingInProgress");
       }
       return env->GetBooleanField(this->obj, isSwingInProgressId);
    }

    void SetSwingInProgress(bool v) {
       if (!SetSwingInProgressId) {
          SetSwingInProgressId = mappings->getField("EntityLivingBase#isSwingInProgress");
       }
       return env->SetBooleanField(this->obj, SetSwingInProgressId, v);
    }

    void setSwingProgressInt(int value) {
       if (!swingProgressIntId) {
          swingProgressIntId = mappings->getField("EntityLivingBase#swingProgressInt");
       }
       env->SetIntField(this->obj, swingProgressIntId, value);
    }

    bool getArmSwingAnimationEnd(bool i) {
       if (!getArmSwingAnimationEndId) {
          getArmSwingAnimationEndId = mappings->getMethod("EntityLivingBase#getArmSwingAnimationEnd");
       }
       return env->CallIntMethod(this->obj, getArmSwingAnimationEndId);
    }

   void setJumping() {
       if (!setJumpingId) {
          setJumpingId = mappings->getMethod("EntityLivingBase#jump");
       }
       this->env->CallBooleanMethod(this->obj, setJumpingId);
    }

    IAttributeInstance getEntityAttribute(IAttribute attribute, JNIEnv* env) {
       if (!env) {
          return { NULL, NULL };
       }

       if (!this->obj) {
          return { NULL, NULL };
       }

       if (!attribute.getObj()) {
          return { NULL, NULL };
       }

       if (!getEntityAttributeId) {
          getEntityAttributeId = mappings->getMethod("EntityLivingBase#getEntityAttribute");
          if (!getEntityAttributeId) {
             return { NULL, NULL };
          }
       }

       if (env->ExceptionCheck()) {
          env->ExceptionClear();
       }

       jobject obj = NULL;
       try {
          obj = env->CallObjectMethod(this->obj, getEntityAttributeId, attribute.getObj());
       }
       catch (...) {
          return { NULL, NULL };
       }

       if (!obj) {
          return { NULL, NULL };
       }

       return { env, obj };
    }

    EnumCreatureAttribute getCreatureAttribute() {
       if (!getCreatureAttributeId) getCreatureAttributeId = mappings->getMethod("EntityLivingBase#getCreatureAttribute");
       jobject obj = this->env->CallObjectMethod(this->obj, getCreatureAttributeId);
       if (!obj) return { NULL, NULL };
       return { this->env, obj };
    }

    Vec3MC GetLook(float partialTicks) {
       if (!getLookId) getLookId = mappings->getMethod("EntityLivingBase#getLook");
       if (!getLookId) return Vec3MC(env, NULL);
       jobject result = this->env->CallObjectMethod(this->obj, getLookId, partialTicks);
       if (!result) return Vec3MC(env, NULL);
       return Vec3MC(this->env, result);
    }

    float moveStrafing() {
       if (!moveStrafingId) moveStrafingId = mappings->getField("EntityLivingBase#moveStrafing");
       return this->env->GetFloatField(this->obj, moveStrafingId);
    }

    bool canEntityBeSeen(Entity entity) {
       if (!canEntityBeSeenId) canEntityBeSeenId = mappings->getMethod("EntityLivingBase#canEntityBeSeen");
       if (entity.isNull()) return false;
       return this->env->CallBooleanMethod(this->obj, canEntityBeSeenId, entity.getObj());
    }

    void swingItem() {
       if (!swingItemId) swingItemId = mappings->getMethod("EntityLivingBase#swingItem");
       this->env->CallVoidMethod(this->obj, swingItemId);
    }

    int getActivePotionEffectsCount() {
        if (!getActivePotionEffectsId)
            getActivePotionEffectsId = mappings->getMethod("EntityLivingBase#getActivePotionEffects");
        jobject collection = this->env->CallObjectMethod(this->obj, getActivePotionEffectsId);
        if (!collection) return 0;
        jclass collClass = this->env->FindClass("java/util/Collection");
        jmethodID sizeId = this->env->GetMethodID(collClass, "size", "()I");
        int count = this->env->CallIntMethod(collection, sizeId);
        this->env->DeleteLocalRef(collection);
        this->env->DeleteLocalRef(collClass);
        return count;
    }
};
