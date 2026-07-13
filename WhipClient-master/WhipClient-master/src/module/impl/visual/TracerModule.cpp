#include "../../../../includes/module/impl/visual/TracerModule.h"

#include <imgui.h>
#include <widgets.h>
#include <algorithm>
#include <GL/gl.h>

#include "../../../../includes/bus/EventBus.h"
#include "../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../includes/wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "../../../../includes/wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../includes/wrapper/minecraft/entity/player/EntityPlayer.h"
#include "../../../../includes/wrapper/java/util/ArrayList.h"
#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../../includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo.h"
#include "../../../../includes/wrapper/java/util/UUID.h"
#include "../../../../includes/util/MathUtils.h"
#include "../../../../includes/module/impl/setting/EnemiesModule.h"
#include "../../../../includes/handler/ProviderHandler.h"
#include "../../../../includes/provider/impl/GameStateProvider.h"
#include "event/sub/RenderWorldEvent.h"
#include "handler/ModuleHandler.h"
#include "module/impl/combat/AntiBotModule.h"

TracerModule::TracerModule(const BindType bindType, const int keyCode)
    : PlayerDataRender3dBaseModule(bindType, keyCode) {

    this->showHealthInfo = false;
    this->showEnemiesOnly = false;
    this->traceAllPlayers = true;
    this->maxRenderDistance = 64.0f;

    this->tracerColor = ImColor(1.0f, 0.0f, 0.0f, 1.0f);
    this->healthBarBg = ImColor(0.2f, 0.2f, 0.2f, 0.8f);
    this->healthBarFull = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    this->healthBarLow = ImColor(1.0f, 0.0f, 0.0f, 1.0f);

    this->tracerWidth = 2.0f;
    this->healthBarWidth = 3.0f;
    this->healthBarHeight = 30.0f;
    this->healthBarOffset = 5.0f;
}

void TracerModule::drawHealthBar2D(const Vector2& pos, const float health, const float maxHealth) {
    if (!showHealthInfo || maxHealth <= 0) return;

    const float healthPercent = std::max(0.0f, std::min(1.0f, health / maxHealth));
    const float barHeight = healthBarHeight * healthPercent;

    setColor(healthBarBg);
    drawRect2D(Vector2(pos.x - healthBarOffset - healthBarWidth, pos.y - healthBarHeight * 0.5f),
               Vector2(pos.x - healthBarOffset, pos.y + healthBarHeight * 0.5f), true);

    const ImVec4 healthBarColor = interpolateColor(healthBarLow, healthBarFull, healthPercent);
    setColor(healthBarColor);
    drawRect2D(Vector2(pos.x - healthBarOffset - healthBarWidth, pos.y + healthBarHeight * 0.5f - barHeight),
               Vector2(pos.x - healthBarOffset, pos.y + healthBarHeight * 0.5f), true);

    setColor(ImVec4(0.0f, 0.0f, 0.0f, 0.8f));
    drawRect2D(Vector2(pos.x - healthBarOffset - healthBarWidth, pos.y - healthBarHeight * 0.5f),
               Vector2(pos.x - healthBarOffset, pos.y + healthBarHeight * 0.5f), false);
}

void TracerModule::collectPlayerData(JNIEnv* env) {
    players.clear();

    if (!env) {
        return;
    }

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) {
        return;
    }

    WorldClient world = mc.theWorld();
    EntityClientPlayerMP localPlayer = mc.thePlayer();
    if (world.isNull() || localPlayer.isNull()) {
        return;
    }

    if (showEnemiesOnly && enemiesModule == nullptr) {
        enemiesModule = static_cast<EnemiesModule*>(ModuleHandler::getInstance().getModule<ModuleType::ENEMY>());
    }
    if (hideFriends && friendsModule == nullptr) {
        friendsModule = static_cast<FriendsModule*>(ModuleHandler::getInstance().getModule<ModuleType::FRIENDS>());
    }

    Vec3D renderPos;

    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        RenderManager renderManager = mc.getRenderManager();
        if (renderManager.isNull()) {
            return;
        }
        renderPos = renderManager.getRenderPos();

        /* explicit DeleteLocalRef removed: renderManager's destructor frees it (double-free crashed Java 25 GC on CheatBreaker) */

    }
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
        RenderManager renderManager = RenderManager::getInstance(env);
        if (renderManager.isNull()) {
            return;
        }
        renderPos = renderManager.getRenderPos();

        /* explicit DeleteLocalRef removed: renderManager's destructor frees it (double-free crashed Java 25 GC on CheatBreaker) */

    }

    const double localPosX = localPlayer.posX();
    const double localPosY = localPlayer.posY();
    const double localPosZ = localPlayer.posZ();
    const double localLastX = localPlayer.lastTickPosX();
    const double localLastY = localPlayer.lastTickPosY();
    const double localLastZ = localPlayer.lastTickPosZ();
    float partialTicks = mc.timer().GetrenderPartialTicks();

    localPlayerPos.x = static_cast<float>(localLastX + (localPosX - localLastX) * partialTicks - renderPos.x);
    localPlayerPos.y = static_cast<float>(localLastY + (localPosY - localLastY) * partialTicks - renderPos.y);
    localPlayerPos.z = static_cast<float>(localLastZ + (localPosZ - localLastZ) * partialTicks - renderPos.z);

    ArrayList playerEntities = world.playerEntities();
    if (playerEntities.isNull()) {
        return;
    }

    const int size = playerEntities.size();

    for (int i = 0; i < size; i++) {
        JavaObject entityObj = playerEntities.get(i);
        auto target = entityObj.convertTo<EntityPlayer>();

        if (target.isNull() || localPlayer.entityId() == target.entityId()) {
            env->DeleteLocalRef(entityObj.getObj());
            env->DeleteLocalRef(target.getObj());
            continue;
        }

        {
            auto* antiBot = AntiBotModule::getInstancePtr();
            if (antiBot && antiBot->isBot(env, target.getObj())) {
                env->DeleteLocalRef(entityObj.getObj());
                env->DeleteLocalRef(target.getObj());
                continue;
            }
        }

        if (hideFriends && friendsModule != nullptr) {
            Entity targetEntity(env, target.getObj());
            targetEntity.setDeleteRef(false);
            if (friendsModule->isFriend(targetEntity)) {
                env->DeleteLocalRef(entityObj.getObj());
                env->DeleteLocalRef(target.getObj());
                continue;
            }
        }

        if (showEnemiesOnly && enemiesModule != nullptr) {
            JavaUUID targetUUID = target.getEntityUniqueID();
            if (targetUUID.isNull()) {
                env->DeleteLocalRef(entityObj.getObj());
                env->DeleteLocalRef(target.getObj());
                continue;
            }

            UUIDData targetUUIDData = targetUUID.toUUIDData();
            bool isEnemy = false;

            for (const auto& enemyUUID : enemiesModule->getEnemyUUIDEntities()) {
                if (targetUUIDData.equals(enemyUUID)) {
                    isEnemy = true;
                    break;
                }
            }

            if (!isEnemy) {
                env->DeleteLocalRef(entityObj.getObj());
                env->DeleteLocalRef(target.getObj());
                continue;
            }
        }

        PlayerData playerData;

        {
            Entity targetEntity(env, target.getObj());
            targetEntity.setDeleteRef(false);
            if (friendsModule && friendsModule->isFriend(targetEntity))
                playerData.relation = PlayerRelation::FRIEND;
            else if (enemiesModule) {
                JavaUUID uuid = target.getEntityUniqueID();
                if (!uuid.isNull()) {
                    UUIDData uuidData = uuid.toUUIDData();
                    for (const auto& eu : enemiesModule->getEnemyUUIDEntities()) {
                        if (uuidData.equals(eu)) { playerData.relation = PlayerRelation::ENEMY; break; }
                    }
                }
            }
        }

        const double targetPosX = target.posX();
        const double targetPosY = target.posY();
        const double targetPosZ = target.posZ();
        const double targetLastX = target.lastTickPosX();
        const double targetLastY = target.lastTickPosY();
        const double targetLastZ = target.lastTickPosZ();
        float partialTicks = mc.timer().GetrenderPartialTicks();

        const double interpX = targetLastX + (targetPosX - targetLastX) * partialTicks - renderPos.x;
        const double interpY = targetLastY + (targetPosY - targetLastY) * partialTicks - renderPos.y;
        const double interpZ = targetLastZ + (targetPosZ - targetLastZ) * partialTicks - renderPos.z;

        playerData.position.x = static_cast<float>(interpX);
        playerData.position.y = static_cast<float>(interpY);
        playerData.position.z = static_cast<float>(interpZ);

        playerData.distance = this->calculateDistance(localPlayerPos, playerData.position);

        if (playerData.distance > maxRenderDistance) {
            env->DeleteLocalRef(entityObj.getObj());
            env->DeleteLocalRef(target.getObj());
            continue;
        }

        playerData.health = target.getHealth();
        playerData.maxHealth = 20.0f;

        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
            if (const jstring nameJString = target.getName()) {
                const char* nameChars = env->GetStringUTFChars(nameJString, nullptr);
                playerData.name = std::string(nameChars);
                env->ReleaseStringUTFChars(nameJString, nameChars);
            }
        }
        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
            if (const jstring nameJString = target.getCommandSenderName()) {
                const char* nameChars = env->GetStringUTFChars(nameJString, nullptr);
                playerData.name = std::string(nameChars);
                env->ReleaseStringUTFChars(nameJString, nameChars);
            }
        }

        playerData.isValid = true;

        calculateBoundingBox(playerData.position, playerData.boundingBox);

        players.push_back(playerData);

        env->DeleteLocalRef(entityObj.getObj());
        env->DeleteLocalRef(target.getObj());
    }

    env->DeleteLocalRef(mc.getObj());
    env->DeleteLocalRef(world.getObj());
    env->DeleteLocalRef(localPlayer.getObj());
    env->DeleteLocalRef(playerEntities.getObj());
}

void TracerModule::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    updateMatrices(env);
    collectPlayerData(env);

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState) return;

    if (!gameState->inGameHasFocus()) return;
    if (gameState->isChestOpen()) return;
    if (gameState->isOptionsOpen()) return;
    if (gameState->isInventoryOpen()) return;

    if (projectionMatrix.size() != 16 || modelViewMatrix.size() != 16) {
        return;
    }

    setupOpenGL(projectionMatrix, modelViewMatrix);

    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadIdentity();
    const ImGuiIO& io = ImGui::GetIO();
    glOrtho(0, io.DisplaySize.x, io.DisplaySize.y, 0, -1, 1);

    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadIdentity();

    const float centerX = io.DisplaySize.x * 0.5f;
    const float centerY = io.DisplaySize.y * 0.5f;

    for (const auto& player : players) {
        if (!player.isValid) continue;

        Vector3 playerCenter = player.position;
        playerCenter.y += 0.9f;

        Vector2 screenPos;
        bool isOnScreen = worldToScreen(playerCenter, screenPos);

        if (!isOnScreen) {
            continue;
        }

        Vector2 tracerEndPoint;
        tracerEndPoint.x = std::max(0.0f, std::min(io.DisplaySize.x, screenPos.x));
        tracerEndPoint.y = std::max(0.0f, std::min(io.DisplaySize.y, screenPos.y));

        bool isPlayerVisible = (screenPos.x >= 0 && screenPos.x <= io.DisplaySize.x &&
                                screenPos.y >= 0 && screenPos.y <= io.DisplaySize.y);

        if (enableTracers) {
            ImColor currentColor = tracerColor;
            if (player.relation == PlayerRelation::FRIEND) currentColor = friendColor;
            else if (player.relation == PlayerRelation::NEUTRAL) currentColor = neutralColor;
            if (!isPlayerVisible) {
                currentColor.Value.w *= 0.5f;
            }

            glLineWidth(tracerWidth);
            setColor(currentColor);

            glBegin(GL_LINES);
            glVertex2f(centerX, centerY);
            glVertex2f(tracerEndPoint.x, tracerEndPoint.y);
            glEnd();
        }

        if (showHealthInfo && isPlayerVisible) {
            drawHealthBar2D(screenPos, player.health, player.maxHealth);
        }
    }

    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();

    restoreOpenGL();
}

bool TracerModule::isPlayerBehindCamera(const Vector3& playerPos, const Vector3& cameraPos, const Vector3& cameraLookAt) {

    Vector3 cameraDirection(
        cameraLookAt.x - cameraPos.x,
        cameraLookAt.y - cameraPos.y,
        cameraLookAt.z - cameraPos.z
    );

    Vector3 toPlayer(
        playerPos.x - cameraPos.x,
        playerPos.y - cameraPos.y,
        playerPos.z - cameraPos.z
    );

    float dotProduct = cameraDirection.x * toPlayer.x +
                       cameraDirection.y * toPlayer.y +
                       cameraDirection.z * toPlayer.z;

    return dotProduct < 0;
}

bool TracerModule::worldToScreen(const Vector3& worldPos, Vector2& screenPos) {
    return Render3dBaseModule::worldToScreen(worldPos, screenPos, projectionMatrix, modelViewMatrix, true);
}

bool TracerModule::updateMatrices(JNIEnv* env) {
    projectionMatrix = ActiveRenderInfo::GetProjectionMatrix(env);
    modelViewMatrix = ActiveRenderInfo::GetModelViewMatrix(env);
    return true;
}

REGISTER_MODULE(TracerModule, ModuleType::TRACER)
