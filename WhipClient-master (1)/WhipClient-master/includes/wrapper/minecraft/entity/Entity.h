#ifndef ENTITY_H_
#define ENTITY_H_

#include <cmath>

#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "../util/text/IChatComponent.h"
#include "axisalignedbb/AxisAlignedBB.h"
#include "../../../../includes/wrapper/java/util/UUID.h"
#include "wrapper/minecraft/util/Vec3.h"

class MovingObjectPosition;
class Vec3MC;
class DamageSource;
class World;

class Entity : public JavaObject {
private:
	static jfieldID posXId;
	static jfieldID posYId;
	static jfieldID posZId;
	static jfieldID lastTickposXId;
	static jfieldID lastTickposYId;
	static jfieldID lastTickposZId;
	static jfieldID motionXId;
	static jfieldID motionYId;
	static jfieldID motionZId;
	static jfieldID setmotionXId;
	static jfieldID setmotionZId;
	static jfieldID setmotionYId;
	static jfieldID serverPosXId;
	static jfieldID serverPosYId;
	static jfieldID serverPosZId;
	static jfieldID rotationYawId;
	static jfieldID rotationPitchId;
	static jfieldID prevRotationYawId;
	static jfieldID prevRotationPitchId;
	static jmethodID getEyeHeightId;
	static jmethodID isSprintingId;
	static jmethodID getFormattedCommandSenderNameId;
	static jmethodID getNameId;
	static jclass entityPlayerClass;
	static jclass entityLivingBaseClass;
	static jfieldID entityIdId;
	static jmethodID setAnglesId;
	static jfieldID pointedEntityId;
	static jfieldID boundingBoxId;
	static jfieldID onGroundId;
	static jmethodID setSprintingId;
	static jfieldID hurtResistantTimeId;
	static jmethodID canAttackWithItemId;
	static jmethodID hitByEntityId;
	static jfieldID velocityChangedId;
	static jfieldID setVelocityChangedId;
	static jmethodID setFireId;
	static jmethodID isBurningId;
	static jmethodID extinguishId;
	static jmethodID attackEntityFromId;
	static jmethodID addVelocityId;
	static jfieldID getFallDistanceId;
	static jmethodID rayTraceId;
	static jmethodID getPositionEyesId;
	static jmethodID getLookId;
	static jmethodID canBeCollidedWithId;
	static jmethodID getCollisionBorderSizeId;
	static jmethodID getEntityBoundingBoxId;
	static jfieldID ridingEntityId;
	static jfieldID entityUniqueIDId;
	static jmethodID setVelocityId;
	static jmethodID isSneakingId;
	static jfieldID worldObjId;
	static jmethodID getPositionId;
	static jmethodID getCommandSenderNameId;
	static jfieldID isDeadid;
	static jmethodID getPositionVectorId;
	static jmethodID isInvisibleId;
	static jmethodID hasCustomNameId;
	static jfieldID ticksExistedId;

public:
	Entity(JNIEnv* env, jobject obj) : JavaObject(env, obj) {}

	int ticksExisted() {
		if (!ticksExistedId) ticksExistedId = mappings->getField("Entity#ticksExisted");
		if (!ticksExistedId) return 0;
		int v = this->env->GetIntField(this->obj, ticksExistedId);
		if (this->env->ExceptionCheck()) { this->env->ExceptionClear(); return 0; }
		return v;
	}

	JavaUUID getEntityUniqueID() {
		if (!entityUniqueIDId) entityUniqueIDId = mappings->getField("Entity#entityUniqueID");

		jobject obj = this->env->GetObjectField(this->obj, entityUniqueIDId);

		if (!obj) return { this->env, nullptr };

		return { this->env, obj };
	}

	bool getVelocityChanged() {
		if (!velocityChangedId) velocityChangedId = mappings->getField("Entity#velocityChanged");
		return this->env->GetBooleanField(this->obj, velocityChangedId);
	}

	bool isDead() {
		if (!isDeadid) isDeadid = mappings->getField("Entity#isDead");
		return this->env->GetBooleanField(this->obj, isDeadid);
	}

	bool isInvisible() {
		if (!isInvisibleId) isInvisibleId = mappings->getMethod("Entity#isInvisible");
		return this->env->CallBooleanMethod(this->obj, isInvisibleId);
	}

	bool hasCustomName() {
		if (!hasCustomNameId) hasCustomNameId = mappings->getMethod("Entity#hasCustomName");
		if (!hasCustomNameId) return false;
		bool result = this->env->CallBooleanMethod(this->obj, hasCustomNameId);
		if (this->env->ExceptionCheck()) {
			this->env->ExceptionClear();
			return false;
		}
		return result;
	}

	void setVelocityChanged(bool changed) {
		if (!setVelocityChangedId) setVelocityChangedId = mappings->getField("Entity#velocityChanged");
		this->env->SetBooleanField(this->obj, setVelocityChangedId, changed);
	}

	void setFire(int ticks) {
		if (!setFireId) setFireId = mappings->getMethod("Entity#setFire");
		this->env->CallVoidMethod(this->obj, setFireId, ticks);
	}

	void setVelocity(double x, double y, double z) {
		if (!setVelocityId) setVelocityId = mappings->getMethod("Entity#setVelocity");
		this->env->CallVoidMethod(this->obj, setVelocityId, x, y, z);
	}

	bool isBurning() {
		if (!isBurningId) isBurningId = mappings->getMethod("Entity#isBurning");
		return this->env->CallBooleanMethod(this->obj, isBurningId);
	}

	void extinguish() {
		if (!extinguishId) extinguishId = mappings->getMethod("Entity#extinguish");
		this->env->CallVoidMethod(this->obj, extinguishId);
	}

	bool attackEntityFrom(DamageSource source, float amount);

	void addVelocity(double x, double y, double z) {
		if (!addVelocityId) addVelocityId = mappings->getMethod("Entity#addVelocity");
		this->env->CallVoidMethod(this->obj, addVelocityId, x, y, z);
	}

	int hurtResistantTime() {
		if (!hurtResistantTimeId) hurtResistantTimeId = mappings->getField("Entity#hurtResistantTime");
		return this->env->GetIntField(this->obj, hurtResistantTimeId);
	}

	double posX() {
		if (!posXId) posXId = mappings->getField("Entity#posX");
		return this->env->GetDoubleField(this->obj, posXId);
	}

	double posY() {
		if (!posYId) posYId = mappings->getField("Entity#posY");
		return this->env->GetDoubleField(this->obj, posYId);
	}

	double posZ() {
		if (!posZId) posZId = mappings->getField("Entity#posZ");
		return this->env->GetDoubleField(this->obj, posZId);
	}

	double lastTickPosX() {
		if (!lastTickposXId) lastTickposXId = mappings->getField("Entity#lastTickPosX");
		return this->env->GetDoubleField(this->obj, lastTickposXId);
	}

	double lastTickPosY() {
		if (!lastTickposYId) lastTickposYId = mappings->getField("Entity#lastTickPosY");
		return this->env->GetDoubleField(this->obj, lastTickposYId);
	}

	double lastTickPosZ() {
		if (!lastTickposZId) lastTickposZId = mappings->getField("Entity#lastTickPosZ");
		return this->env->GetDoubleField(this->obj, lastTickposZId);
	}

	void setPosX(double value) {
		if (!posXId) posXId = mappings->getField("Entity#posX");
		this->env->SetDoubleField(this->obj, posXId, value);
	}

	void setPosY(double value) {
		if (!posYId) posYId = mappings->getField("Entity#posY");
		this->env->SetDoubleField(this->obj, posYId, value);
	}

	void setPosZ(double value) {
		if (!posZId) posZId = mappings->getField("Entity#posZ");
		this->env->SetDoubleField(this->obj, posZId, value);
	}

	void setLastTickPosX(double value) {
		if (!lastTickposXId) lastTickposXId = mappings->getField("Entity#lastTickPosX");
		this->env->SetDoubleField(this->obj, lastTickposXId, value);
	}

	void setLastTickPosY(double value) {
		if (!lastTickposYId) lastTickposYId = mappings->getField("Entity#lastTickPosY");
		this->env->SetDoubleField(this->obj, lastTickposYId, value);
	}

	void setLastTickPosZ(double value) {
		if (!lastTickposZId) lastTickposZId = mappings->getField("Entity#lastTickPosZ");
		this->env->SetDoubleField(this->obj, lastTickposZId, value);
	}

	double prevPosX() {
		if (!lastTickposXId) lastTickposXId = mappings->getField("Entity#prevPosX");
		return this->env->GetDoubleField(this->obj, lastTickposXId);
	}

	double prevPosY() {
		if (!lastTickposYId) lastTickposYId = mappings->getField("Entity#prevPosY");
		return this->env->GetDoubleField(this->obj, lastTickposYId);
	}

	double prevPosZ() {
		if (!lastTickposZId) lastTickposZId = mappings->getField("Entity#prevPosZ");
		return this->env->GetDoubleField(this->obj, lastTickposZId);
	}

	double motionX() {
		if (!motionXId) motionXId = mappings->getField("Entity#motionX");
		return this->env->GetDoubleField(this->obj, motionXId);
	}

	double motionY() {
		if (!motionYId) motionYId = mappings->getField("Entity#motionY");
		return this->env->GetDoubleField(this->obj, motionYId);
	}

	double motionZ() {
		if (!motionZId) motionZId = mappings->getField("Entity#motionZ");
		return this->env->GetDoubleField(this->obj, motionZId);
	}

	void setMotionX(double value) {
		if (!setmotionXId) setmotionXId = mappings->getField("Entity#motionX");
		this->env->SetDoubleField(this->obj, setmotionXId, value);
	}

	void setMotionZ(double value) {
		if (!setmotionZId) setmotionZId = mappings->getField("Entity#motionZ");
		this->env->SetDoubleField(this->obj, setmotionZId, value);
	}

	void setMotionY(double value) {
		if (!setmotionYId) setmotionYId = mappings->getField("Entity#motionY");
		this->env->SetDoubleField(this->obj, setmotionYId, value);
	}

	long long serverPosX() {
		if (!serverPosXId) serverPosXId = mappings->getField("Entity#serverPosX");
		return (long long)this->env->GetIntField(this->obj, serverPosXId);
	}

	long long serverPosY() {
		if (!serverPosYId) serverPosYId = mappings->getField("Entity#serverPosY");
		return (long long)this->env->GetIntField(this->obj, serverPosYId);
	}

	long long serverPosZ() {
		if (!serverPosZId) serverPosZId = mappings->getField("Entity#serverPosZ");
		return (long long)this->env->GetIntField(this->obj, serverPosZId);
	}

	float getFallDistance() {
		if (!getFallDistanceId) getFallDistanceId = mappings->getField("Entity#fallDistance");
		return this->env->GetFloatField(this->obj, getFallDistanceId);
	}

	float rotationYaw() {
		if (!rotationYawId) rotationYawId = mappings->getField("Entity#rotationYaw");
		return this->env->GetFloatField(this->obj, rotationYawId);
	}

	void rotationYaw(float f) {
		if (!rotationYawId) rotationYawId = mappings->getField("Entity#rotationYaw");
		this->env->SetFloatField(this->obj, rotationYawId, f);
	}

	float rotationPitch() {
		if (!rotationPitchId) rotationPitchId = mappings->getField("Entity#rotationPitch");
		return this->env->GetFloatField(this->obj, rotationPitchId);
	}

	void rotationPitch(float f) {
		if (!rotationPitchId) rotationPitchId = mappings->getField("Entity#rotationPitch");
		this->env->SetFloatField(this->obj, rotationPitchId, f);
	}

	float prevRotationYaw() {
		if (!prevRotationYawId) prevRotationYawId = mappings->getField("Entity#prevRotationYaw");
		return this->env->GetFloatField(this->obj, prevRotationYawId);
	}

	void prevRotationYaw(float f) {
		if (!prevRotationYawId) prevRotationYawId = mappings->getField("Entity#prevRotationYaw");
		this->env->SetFloatField(this->obj, prevRotationYawId, f);
	}

	float prevRotationPitch() {
		if (!prevRotationPitchId) prevRotationPitchId = mappings->getField("Entity#prevRotationPitch");
		return this->env->GetFloatField(this->obj, prevRotationPitchId);
	}

	float getEyeHeight() {
		if (!getEyeHeightId) getEyeHeightId = mappings->getMethod("Entity#getEyeHeight");
		return this->env->CallFloatMethod(this->obj, getEyeHeightId);
	}

	void prevRotationPitch(float f) {
		if (!prevRotationPitchId) prevRotationPitchId = mappings->getField("Entity#prevRotationPitch");
		this->env->SetFloatField(this->obj, prevRotationPitchId, f);
	}

	jstring getName() {
		if (!getNameId) getNameId = mappings->getMethod("Entity#getName");

		return (jstring) this->env->CallObjectMethod(this->obj, getNameId);
	}

	jstring getCommandSenderName() {
		if (!getCommandSenderNameId) getCommandSenderNameId = mappings->getMethod("Entity#getName");

		return (jstring) this->env->CallObjectMethod(this->obj, getCommandSenderNameId);
	}

	IChatComponent getFormattedCommandSenderName() {
		if (!getFormattedCommandSenderNameId) getFormattedCommandSenderNameId = mappings->getMethod("Entity#getDisplayName");
		jobject obj = this->env->CallObjectMethod(this->obj, getFormattedCommandSenderNameId);
		if (!obj) return IChatComponent(this->env, NULL);
		return IChatComponent(this->env, obj);
	}

	bool isPlayer() {
		if (!entityPlayerClass) entityPlayerClass = mappings->getClass("EntityPlayer");
		return this->env->IsInstanceOf(this->obj, entityPlayerClass);
	}

	bool isLivingEntity() {
		if (!entityLivingBaseClass) entityLivingBaseClass = mappings->getClass("EntityLivingBase");
		return this->env->IsInstanceOf(this->obj, entityLivingBaseClass);
	}

	bool isSprinting() {
		if (!isSprintingId) isSprintingId = mappings->getMethod("Entity#isSprinting");
		return this->env->CallBooleanMethod(this->obj, isSprintingId);
	}

	bool isSneaking() {
		if (!isSneakingId) isSneakingId = mappings->getMethod("Entity#isSneaking");

		return this->env->CallBooleanMethod(this->obj, isSneakingId);
	}

	bool canAttackWithItem() {
		if (!canAttackWithItemId) canAttackWithItemId = mappings->getMethod("Entity#canAttackWithItem");
		return this->env->CallBooleanMethod(this->obj, canAttackWithItemId);
	}

	int entityId() {
		if (!entityIdId) entityIdId = mappings->getField("Entity#entityId");
		return this->env->GetIntField(this->obj, entityIdId);
	}

	void setAngles(float yaw, float pitch) {
		if (!setAnglesId) setAnglesId = mappings->getMethod("Entity#setAngles");
		this->env->CallVoidMethod(this->obj, setAnglesId, yaw, pitch);
	}

	bool hitByEntity(Entity entity) {
		if (!hitByEntityId) hitByEntityId = mappings->getMethod("Entity#hitByEntity");
		return this->env->CallBooleanMethod(this->obj, hitByEntityId, entity.getObj());
	}

	float getDistanceToEntity(Entity entityIn) {
		if (entityIn.isNull()) return 0.0f;

		float xDiff = (float)(posX() - entityIn.posX());
		float yDiff = (float)(posY() - entityIn.posY());
		float zDiff = (float)(posZ() - entityIn.posZ());

		return sqrt(xDiff * xDiff + yDiff * yDiff + zDiff * zDiff);
	}

	bool onGround() {
		if (!onGroundId) onGroundId = mappings->getField("Entity#onGround");
		return this->env->GetBooleanField(this->obj, onGroundId);
	}

	void setSprinting(bool sprint) {
		if (!setSprintingId) setSprintingId = mappings->getMethod("Entity#setSprinting");
		this->env->CallVoidMethod(this->obj, setSprintingId, (jboolean)sprint);
	}

	AxisAlignedBB getBoundingBox() const {
		if (!boundingBoxId) boundingBoxId = mappings->getField("Entity#boundingBox");
		jobject bbObj = this->env->GetObjectField(this->obj, boundingBoxId);
		return AxisAlignedBB(this->env, bbObj);
	}

	MovingObjectPosition rayTrace(double distance, float partialTicks);
	Vec3MC getPositionEyes(float partialTicks);
	Vec3MC getPosition(float partialTicks);
	Vec3MC getLook(float partialTicks);
	AxisAlignedBB getEntityBoundingBox();

	bool canBeCollidedWith() {
		if (!canBeCollidedWithId) canBeCollidedWithId = mappings->getMethod("Entity#canBeCollidedWith");
		return this->env->CallBooleanMethod(this->obj, canBeCollidedWithId);
	}

	float getCollisionBorderSize() {
		if (!getCollisionBorderSizeId) getCollisionBorderSizeId = mappings->getMethod("Entity#getCollisionBorderSize");
		return this->env->CallFloatMethod(this->obj, getCollisionBorderSizeId);
	}

	Vec3MC getPositionVector() {
		if (!getPositionVectorId) getPositionVectorId = mappings->getMethod("Entity#getPositionVector");
		jobject vec3Obj = this->env->CallObjectMethod(this->obj, getPositionVectorId);
		return Vec3MC(this->env, vec3Obj);
	}

	Entity getRidingEntity() {
		if (!ridingEntityId) ridingEntityId = mappings->getField("Entity#ridingEntity");
		jobject obj = this->env->GetObjectField(this->obj, ridingEntityId);
		if (!obj) return Entity(NULL, NULL);
		return Entity(this->env, obj);
	}

	Vec3MC getVectorForRotation(float pitch, float yaw)
	{
		float f = std::cos(-yaw * 0.017453292F - (float)3.14159265358979323846);
		float f1 = std::sin(-yaw * 0.017453292F - (float)3.14159265358979323846);
		float f2 = -std::cos(-pitch * 0.017453292F);
		float f3 = std::sin(-pitch * 0.017453292F);
		return Vec3MC(env, (double)(f1 * f2), (double)f3, (double)(f * f2));
	}

	World worldObj();
};

#endif
