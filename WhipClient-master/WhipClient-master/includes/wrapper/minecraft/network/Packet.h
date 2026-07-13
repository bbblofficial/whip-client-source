#pragma once
#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "attackpacket.h"

class Packet : public JavaObject {
    static jmethodID processPacketId;
    static jclass IsTeamsPacketClass;
    static jclass IsSpawnPlayerPacketClass;
    static jclass IsScoreboardObjectivePacketClass;
    static jclass IsEntityTeleportPacketClass;
    static jclass IsEntityPacketClass;
    static jclass IsEntityVeloPacketClass;
    static jclass IsEntityVelo2PacketClass;
    static jclass S12PacketEntityVelocityClass2;

    static jclass S0EPacketSpawnObjectClass;
    static jclass S11PacketSpawnExperienceOrbClass;
    static jclass S2CPacketSpawnGlobalEntityClass;
    static jclass S0FPacketSpawnMobClass;
    static jclass S3BPacketScoreboardObjectiveClass;
    static jclass S10PacketSpawnPaintingClass;
    static jclass S0CPacketSpawnPlayerClass;
    static jclass S0BPacketAnimationClass;
    static jclass S37PacketStatisticsClass;
    static jclass S25PacketBlockBreakAnimClass;
    static jclass S36PacketSignEditorOpenClass;
    static jclass S35PacketUpdateTileEntityClass;
    static jclass S24PacketBlockActionClass;
    static jclass S23PacketBlockChangeClass;
    static jclass S02PacketChatClass;
    static jclass S3APacketTabCompleteClass;
    static jclass S22PacketMultiBlockChangeClass;
    static jclass S34PacketMapsClass;
    static jclass S32PacketConfirmTransactionClass;
    static jclass S2EPacketCloseWindowClass;
    static jclass S30PacketWindowItemsClass;
    static jclass S2DPacketOpenWindowClass;
    static jclass S31PacketWindowPropertyClass;
    static jclass S2FPacketSetSlotClass;
    static jclass S3FPacketCustomPayloadClass;
    static jclass S0APacketUseBedClass;
    static jclass S19PacketEntityStatusClass;
    static jclass S1BPacketEntityAttachClass;
    static jclass S27PacketExplosionClass;
    static jclass S2BPacketChangeGameStateClass;
    static jclass S00PacketKeepAliveClass;
    static jclass S21PacketChunkDataClass;
    static jclass S26PacketMapChunkBulkClass;
    static jclass S28PacketEffectClass;
    static jclass S14PacketEntityClass;
    static jclass S08PacketPlayerPosLookClass;
    static jclass S2APacketParticlesClass;
    static jclass S39PacketPlayerAbilitiesClass;
    static jclass S38PacketPlayerListItemClass;
    static jclass S13PacketDestroyEntitiesClass;
    static jclass S1EPacketRemoveEntityEffectClass;
    static jclass S07PacketRespawnClass;
    static jclass S19PacketEntityHeadLookClass;
    static jclass S09PacketHeldItemChangeClass;
    static jclass S3DPacketDisplayScoreboardClass;
    static jclass S1CPacketEntityMetadataClass;
    static jclass S12PacketEntityVelocityClass;
    static jclass S04PacketEntityEquipmentClass;
    static jclass S1FPacketSetExperienceClass;
    static jclass S06PacketUpdateHealthClass;
    static jclass S3EPacketTeamsClass;
    static jclass S3CPacketUpdateScoreClass;
    static jclass S05PacketSpawnPositionClass;
    static jclass S03PacketTimeUpdateClass;
    static jclass S33PacketUpdateSignClass;
    static jclass S29PacketSoundEffectClass;
    static jclass S0DPacketCollectItemClass;
    static jclass S18PacketEntityTeleportClass;
    static jclass S20PacketEntityPropertiesClass;
    static jclass S1DPacketEntityEffectClass;
    static jclass S42PacketCombatEventClass;
    static jclass S41PacketServerDifficultyClass;
    static jclass S43PacketCameraClass;
    static jclass S44PacketWorldBorderClass;
    static jclass S45PacketTitleClass;
    static jclass S46PacketSetCompressionLevelClass;
    static jclass S47PacketPlayerListHeaderFooterClass;
    static jclass S48PacketResourcePackSendClass;
    static jclass S49PacketUpdateEntityNBTClass;
    static jclass C07PacketPlayerDiggingClass2;

    jobject InstanceObject;

public:
    Packet(JNIEnv* env, jobject obj) : JavaObject(env, obj) {

        if (!env || !obj) {
            return;
        }

        jclass velocityPacketClass = mappings->getClass("S12PacketEntityVelocity");
        if (!velocityPacketClass) {
            return;
        }

        makeGlobalRef();
    }

    void processPacket(JavaObject netHandler) {
        if (!processPacketId) processPacketId = mappings->getMethod("Packet#processPacket");
        this->env->CallVoidMethod(this->obj, processPacketId, netHandler.getObj());
    }

    bool IsTeamsPacket(JNIEnv* Env) {

        if (!IsTeamsPacketClass) IsTeamsPacketClass = mappings->getClass("S3EPacketTeams");

        return this->isInstanceOf(IsTeamsPacketClass);
    }

    bool IsSpawnPlayerPacket(JNIEnv* Env) {

        if (!IsSpawnPlayerPacketClass) IsSpawnPlayerPacketClass = mappings->getClass("S0CPacketSpawnPlayer");

        return this->isInstanceOf(IsSpawnPlayerPacketClass);
    }

    bool IsScoreboardObjectivePacket(JNIEnv* Env) {

        if (!IsScoreboardObjectivePacketClass) IsScoreboardObjectivePacketClass = mappings->getClass("S3BPacketScoreboardObjective");

        return this->isInstanceOf(IsScoreboardObjectivePacketClass);
    }

    bool IsEntityTeleportPacket(JNIEnv* Env) {

        if (!IsEntityTeleportPacketClass) IsEntityTeleportPacketClass = mappings->getClass("S18PacketEntityTeleport");

        return this->isInstanceOf(IsEntityTeleportPacketClass);
    }

    bool IsEntityVelo2() {

        if (!IsEntityVelo2PacketClass) IsEntityVelo2PacketClass = mappings->getClass("S19PacketEntityStatus");

        return this->isInstanceOf(IsEntityVelo2PacketClass);
    }

    bool IsC07PacketPlayerDigging() {

        if (!C07PacketPlayerDiggingClass2) C07PacketPlayerDiggingClass2 = mappings->getClass("C07PacketPlayerDigging");

        return this->isInstanceOf(C07PacketPlayerDiggingClass2);
    }

    bool IsS12PacketEntityVelocity() {

        if (!S12PacketEntityVelocityClass2) S12PacketEntityVelocityClass2 = mappings->getClass("S12PacketEntityVelocity");

        return this->isInstanceOf(S12PacketEntityVelocityClass2);
    }

    bool IsEntityVelo() {

        if (!IsEntityVeloPacketClass) IsEntityVeloPacketClass = mappings->getClass("S12PacketEntityVelocity");

        return this->isInstanceOf(IsEntityVeloPacketClass);
    }

    bool IsEntityPacket() {

        if (!IsEntityPacketClass) IsEntityPacketClass = mappings->getClass("S14PacketEntity");

        return this->isInstanceOf(IsEntityPacketClass);
    }

    bool IsAttackPacket(JNIEnv* Env, const int SelfEntityID) {

        if (!IsEntityPacketClass) {
            IsEntityPacketClass = mappings->getClass("S14PacketEntity");
        }

        AttackPacket attackpacket(Env, InstanceObject);
        return attackpacket.entityId() == SelfEntityID && attackpacket.GetLogicOpCode() == static_cast<jbyte>(2);
    }

    bool IsPlayClientPacket(jobject packetObj) const
    {

        if (!env || !packetObj) {
            return false;
        }

        jclass packetClass = env->GetObjectClass(packetObj);
        if (!packetClass) {
            return false;
        }

        jmethodID getClassMethod = env->GetMethodID(packetClass, "getClass", "()Ljava/lang/Class;");
        if (!getClassMethod) {
            env->DeleteLocalRef(packetClass);
            return false;
        }

        jobject classObject = env->CallObjectMethod(packetObj, getClassMethod);
        if (!classObject) {
            env->DeleteLocalRef(packetClass);
            return false;
        }

        jmethodID getNameMethod = env->GetMethodID(env->GetObjectClass(classObject), "getName", "()Ljava/lang/String;");
        if (!getNameMethod) {
            env->DeleteLocalRef(classObject);
            env->DeleteLocalRef(packetClass);
            return false;
        }

        jstring className = (jstring)env->CallObjectMethod(classObject, getNameMethod);
        if (!className) {
            env->DeleteLocalRef(classObject);
            env->DeleteLocalRef(packetClass);
            return false;
        }

        const char* nativeString = env->GetStringUTFChars(className, nullptr);
        std::string packetName(nativeString);

        env->ReleaseStringUTFChars(className, nativeString);
        env->DeleteLocalRef(className);
        env->DeleteLocalRef(classObject);
        env->DeleteLocalRef(packetClass);

        return (
            packetName.find("S0EPacketSpawnObject") != std::string::npos ||
            packetName.find("S11PacketSpawnExperienceOrb") != std::string::npos ||
            packetName.find("S2CPacketSpawnGlobalEntity") != std::string::npos ||
            packetName.find("S0FPacketSpawnMob") != std::string::npos ||
            packetName.find("S3BPacketScoreboardObjective") != std::string::npos ||
            packetName.find("S10PacketSpawnPainting") != std::string::npos ||
            packetName.find("S0CPacketSpawnPlayer") != std::string::npos ||
            packetName.find("S0BPacketAnimation") != std::string::npos ||
            packetName.find("S37PacketStatistics") != std::string::npos ||
            packetName.find("S25PacketBlockBreakAnim") != std::string::npos ||
            packetName.find("S36PacketSignEditorOpen") != std::string::npos ||
            packetName.find("S35PacketUpdateTileEntity") != std::string::npos ||
            packetName.find("S24PacketBlockAction") != std::string::npos ||
            packetName.find("S23PacketBlockChange") != std::string::npos ||
            packetName.find("S02PacketChat") != std::string::npos ||
            packetName.find("S3APacketTabComplete") != std::string::npos ||
            packetName.find("S22PacketMultiBlockChange") != std::string::npos ||
            packetName.find("S34PacketMaps") != std::string::npos ||
            packetName.find("S32PacketConfirmTransaction") != std::string::npos ||
            packetName.find("S2EPacketCloseWindow") != std::string::npos ||
            packetName.find("S30PacketWindowItems") != std::string::npos ||
            packetName.find("S2DPacketOpenWindow") != std::string::npos ||
            packetName.find("S31PacketWindowProperty") != std::string::npos ||
            packetName.find("S2FPacketSetSlot") != std::string::npos ||
            packetName.find("S3FPacketCustomPayload") != std::string::npos ||
            packetName.find("S0APacketUseBed") != std::string::npos ||
            packetName.find("S19PacketEntityStatus") != std::string::npos ||
            packetName.find("S1BPacketEntityAttach") != std::string::npos ||
            packetName.find("S27PacketExplosion") != std::string::npos ||
            packetName.find("S2BPacketChangeGameState") != std::string::npos ||
            packetName.find("S00PacketKeepAlive") != std::string::npos ||
            packetName.find("S21PacketChunkData") != std::string::npos ||
            packetName.find("S26PacketMapChunkBulk") != std::string::npos ||
            packetName.find("S28PacketEffect") != std::string::npos ||
            packetName.find("S14PacketEntity") != std::string::npos ||
            packetName.find("S08PacketPlayerPosLook") != std::string::npos ||
            packetName.find("S2APacketParticles") != std::string::npos ||
            packetName.find("S39PacketPlayerAbilities") != std::string::npos ||
            packetName.find("S38PacketPlayerListItem") != std::string::npos ||
            packetName.find("S13PacketDestroyEntities") != std::string::npos ||
            packetName.find("S1EPacketRemoveEntityEffect") != std::string::npos ||
            packetName.find("S07PacketRespawn") != std::string::npos ||
            packetName.find("S19PacketEntityHeadLook") != std::string::npos ||
            packetName.find("S09PacketHeldItemChange") != std::string::npos ||
            packetName.find("S3DPacketDisplayScoreboard") != std::string::npos ||
            packetName.find("S1CPacketEntityMetadata") != std::string::npos ||
            packetName.find("S12PacketEntityVelocity") != std::string::npos ||
            packetName.find("S04PacketEntityEquipment") != std::string::npos ||
            packetName.find("S1FPacketSetExperience") != std::string::npos ||
            packetName.find("S06PacketUpdateHealth") != std::string::npos ||
            packetName.find("S3EPacketTeams") != std::string::npos ||
            packetName.find("S3CPacketUpdateScore") != std::string::npos ||
            packetName.find("S05PacketSpawnPosition") != std::string::npos ||
            packetName.find("S03PacketTimeUpdate") != std::string::npos ||
            packetName.find("S33PacketUpdateSign") != std::string::npos ||
            packetName.find("S29PacketSoundEffect") != std::string::npos ||
            packetName.find("S0DPacketCollectItem") != std::string::npos ||
            packetName.find("S18PacketEntityTeleport") != std::string::npos ||
            packetName.find("S20PacketEntityProperties") != std::string::npos ||
            packetName.find("S1DPacketEntityEffect") != std::string::npos ||
            packetName.find("S42PacketCombatEvent") != std::string::npos ||
            packetName.find("S41PacketServerDifficulty") != std::string::npos ||
            packetName.find("S43PacketCamera") != std::string::npos ||
            packetName.find("S44PacketWorldBorder") != std::string::npos ||
            packetName.find("S45PacketTitle") != std::string::npos ||
            packetName.find("S46PacketSetCompressionLevel") != std::string::npos ||
            packetName.find("S47PacketPlayerListHeaderFooter") != std::string::npos ||
            packetName.find("S48PacketResourcePackSend") != std::string::npos ||
            packetName.find("S49PacketUpdateEntityNBT") != std::string::npos
            );
    }

};
