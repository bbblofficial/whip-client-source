#include "../../../../includes/module/impl/visual/EspModule.h"
#include "handler/MappingHandler.h"

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
#include "../../../../includes/util/MathUtils.h"
#include "../../../../includes/module/impl/setting/EnemiesModule.h"
#include "../../../../includes/handler/ProviderHandler.h"
#include "../../../../includes/provider/impl/GameStateProvider.h"
#include "../../../../includes/wrapper/minecraft/util/ResourceLocation.h"
#include "event/sub/RenderWorldEvent.h"
#include "handler/ModuleHandler.h"
#include "module/impl/combat/AntiBotModule.h"

ESPModule::ESPModule(const BindType bindType, const int keyCode)
    : PlayerDataRender3dBaseModule(bindType, keyCode) {

    this->renderMode = 1;
    this->mode3d = 2;
    this->mode2d = 2;
    this->showHealthBar = true;
    this->showEnemiesOnly = false;
    this->maxRenderDistance = 64.0f;

    this->outline3dColor = ImColor(0.0f, 127.0f, 245.0f, 1.0f);
    this->fill3dColor = ImColor(0.0f, 127.0f, 245.0f, 0.1f);
    this->outline2dColor = ImColor(0.0f, 127.0f, 245.0f, 1.0f);
    this->fill2dColor = ImColor(0.0f, 127.0f, 245.0f, 0.2f);
    this->healthBarBg = ImColor(0.2f, 0.2f, 0.2f, 0.8f);
    this->healthBarFull = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    this->healthBarLow = ImColor(1.0f, 0.0f, 0.0f, 1.0f);

    this->outline3dWidth = 2.0f;
    this->outline2dWidth = 1.5f;
    this->healthBarWidth = 3.0f;
    this->healthBarHeight = 30.0f;
    this->healthBarOffset = 5.0f;
}

float ESPModule::calculateSmoothScale(float distance, float minDist, float maxDist, float minScale, float maxScale) {

    distance = std::max(minDist, std::min(maxDist, distance));

    float t = (distance - minDist) / (maxDist - minDist);

    t = 1.0f - t;

    float smoothT = t * t * (3.0f - 2.0f * t);

    smoothT = smoothT * smoothT * (3.0f - 2.0f * smoothT);

    return minScale + smoothT * (maxScale - minScale);
}

void ESPModule::drawHealthBar2D(const Vector2& pos, const float boxHeight, const float health, const float maxHealth) {
    if (!showHealthBar || maxHealth <= 0) return;

    const float healthPercent = std::max(0.0f, std::min(1.0f, health / maxHealth));
    const float barHeight = boxHeight * healthPercent;

    setColor(healthBarBg);
    drawRect2D(Vector2(pos.x - healthBarOffset - healthBarWidth, pos.y - boxHeight * 0.5f),
               Vector2(pos.x - healthBarOffset, pos.y + boxHeight * 0.5f), true);

    const ImVec4 healthBarColor = interpolateColor(healthBarLow, healthBarFull, healthPercent);
    setColor(healthBarColor);
    drawRect2D(Vector2(pos.x - healthBarOffset - healthBarWidth, pos.y + boxHeight * 0.5f - barHeight),
               Vector2(pos.x - healthBarOffset, pos.y + boxHeight * 0.5f), true);

    setColor(ImVec4(0.0f, 0.0f, 0.0f, 0.8f));
    drawRect2D(Vector2(pos.x - healthBarOffset - healthBarWidth, pos.y - boxHeight * 0.5f),
               Vector2(pos.x - healthBarOffset, pos.y + boxHeight * 0.5f), false);
}

void ESPModule::drawHearts2D(JNIEnv* env, const Vector2& topLeft, float boxWidth, float boxHeight, float distance, float health, float maxHealth) {
    if (!showHearts || maxHealth <= 0) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    TextureManager textureManager = mc.getTextureManager();
    if (textureManager.isNull()) return;

    ResourceLocation icons(env, "textures/gui/icons.png");
    if (icons.isNull()) return;

    textureManager.bindTexture(icons);

    glEnable(GL_TEXTURE_2D);
    glColor4f(1.0f, 1.0f, 1.0f, 1.0f);

    const int maxHearts = static_cast<int>(std::ceil(maxHealth / 2.0f));
    const int currentHealth = static_cast<int>(std::ceil(health));

    const float scaleFactor = std::clamp(boxHeight / 100.0f, 0.4f, 2.5f);

    const float heartSize = 9.0f * scaleFactor;
    const float heartSpacing = 8.0f * scaleFactor;
    const float totalWidth = maxHearts * heartSpacing;
    const float startX = topLeft.x + (boxWidth - totalWidth) / 2.0f;
    const float heartsY = topLeft.y - (12.0f * scaleFactor);

    const float uScale = 1.0f / 256.0f;
    const float vScale = 1.0f / 256.0f;

    const float uEmpty = 16.0f * uScale;
    const float uFull = 52.0f * uScale;
    const float uHalf = 61.0f * uScale;
    const float v0 = 0.0f;
    const float uWidth = 9.0f * uScale;
    const float vHeight = 9.0f * vScale;

    for (int i = 0; i < maxHearts; ++i) {
        const float hX = startX + (i * heartSpacing);

        glBegin(GL_QUADS);
        glTexCoord2f(uEmpty, v0);
        glVertex2f(hX, heartsY);
        glTexCoord2f(uEmpty + uWidth, v0);
        glVertex2f(hX + heartSize, heartsY);
        glTexCoord2f(uEmpty + uWidth, v0 + vHeight);
        glVertex2f(hX + heartSize, heartsY + heartSize);
        glTexCoord2f(uEmpty, v0 + vHeight);
        glVertex2f(hX, heartsY + heartSize);
        glEnd();

        const int heartValue = (i * 2) + 1;

        if (currentHealth > heartValue) {

            glBegin(GL_QUADS);
            glTexCoord2f(uFull, v0);
            glVertex2f(hX, heartsY);
            glTexCoord2f(uFull + uWidth, v0);
            glVertex2f(hX + heartSize, heartsY);
            glTexCoord2f(uFull + uWidth, v0 + vHeight);
            glVertex2f(hX + heartSize, heartsY + heartSize);
            glTexCoord2f(uFull, v0 + vHeight);
            glVertex2f(hX, heartsY + heartSize);
            glEnd();
        } else if (currentHealth == heartValue) {

            glBegin(GL_QUADS);
            glTexCoord2f(uHalf, v0);
            glVertex2f(hX, heartsY);
            glTexCoord2f(uHalf + uWidth, v0);
            glVertex2f(hX + heartSize, heartsY);
            glTexCoord2f(uHalf + uWidth, v0 + vHeight);
            glVertex2f(hX + heartSize, heartsY + heartSize);
            glTexCoord2f(uHalf, v0 + vHeight);
            glVertex2f(hX, heartsY + heartSize);
            glEnd();
        }
    }

    glDisable(GL_TEXTURE_2D);
}

void ESPModule::drawArmor2D(JNIEnv* env, const Vector2& topLeft, float boxWidth, float boxHeight, float distance, const std::array<jobject, 4>& armorItems) {
    if (!showArmor) return;

    int equippedCount = 0;
    for (jobject item : armorItems) {
        if (item != nullptr) equippedCount++;
    }

    if (equippedCount == 0) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    TextureManager textureManager = mc.getTextureManager();
    if (textureManager.isNull()) return;

    const float scaleFactor = std::clamp(boxHeight / 100.0f, 0.4f, 2.5f);

    const float armorIconSize = 16.0f * scaleFactor;
    const float armorSpacing = 18.0f * scaleFactor;

    const float totalWidth = equippedCount * armorSpacing;
    float currentX = topLeft.x + (boxWidth - totalWidth) / 2.0f;
    const float armorY = topLeft.y - (28.0f * scaleFactor);

    glEnable(GL_TEXTURE_2D);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glColor4f(1.0f, 1.0f, 1.0f, 1.0f);

    auto getArmorTexturePath = [](int itemId) -> const char* {

        if (itemId == 310) return "textures/items/diamond_helmet.png";
        if (itemId == 311) return "textures/items/diamond_chestplate.png";
        if (itemId == 312) return "textures/items/diamond_leggings.png";
        if (itemId == 313) return "textures/items/diamond_boots.png";

        if (itemId == 306) return "textures/items/iron_helmet.png";
        if (itemId == 307) return "textures/items/iron_chestplate.png";
        if (itemId == 308) return "textures/items/iron_leggings.png";
        if (itemId == 309) return "textures/items/iron_boots.png";

        if (itemId == 314) return "textures/items/gold_helmet.png";
        if (itemId == 315) return "textures/items/gold_chestplate.png";
        if (itemId == 316) return "textures/items/gold_leggings.png";
        if (itemId == 317) return "textures/items/gold_boots.png";

        if (itemId == 302) return "textures/items/chainmail_helmet.png";
        if (itemId == 303) return "textures/items/chainmail_chestplate.png";
        if (itemId == 304) return "textures/items/chainmail_leggings.png";
        if (itemId == 305) return "textures/items/chainmail_boots.png";

        if (itemId == 298) return "textures/items/leather_helmet.png";
        if (itemId == 299) return "textures/items/leather_chestplate.png";
        if (itemId == 300) return "textures/items/leather_leggings.png";
        if (itemId == 301) return "textures/items/leather_boots.png";

        return nullptr;
    };

    for (int i = 3; i >= 0; --i) {
        if (armorItems[i] != nullptr) {
            ItemStack armorStack(env, armorItems[i]);

            if (!armorStack.isNull()) {
                int itemId = armorStack.getItemId();
                const char* texturePath = getArmorTexturePath(itemId);

                if (texturePath) {

                    ResourceLocation armorTexture(env, texturePath);
                    if (!armorTexture.isNull()) {
                        textureManager.bindTexture(armorTexture);

                        glBegin(GL_QUADS);
                        glTexCoord2f(0.0f, 0.0f);
                        glVertex2f(currentX, armorY);
                        glTexCoord2f(1.0f, 0.0f);
                        glVertex2f(currentX + armorIconSize, armorY);
                        glTexCoord2f(1.0f, 1.0f);
                        glVertex2f(currentX + armorIconSize, armorY + armorIconSize);
                        glTexCoord2f(0.0f, 1.0f);
                        glVertex2f(currentX, armorY + armorIconSize);
                        glEnd();
                    }
                }
            }

            currentX += armorSpacing;
        }
    }

    glDisable(GL_TEXTURE_2D);
    glDisable(GL_BLEND);
}

void ESPModule::collectPlayerData(JNIEnv* env) {

    for (auto& player : players) {
        for (jobject armorItem : player.armorItems) {
            if (armorItem != nullptr) {
                env->DeleteGlobalRef(armorItem);
            }
        }
    }

    players.clear();

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
    if (friendsModule == nullptr) {
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

        if (showArmor) {
            InventoryPlayer inventory = target.inventoryPlayer();
            if (!inventory.isNull()) {
                for (int armorSlot = 0; armorSlot < 4; armorSlot++) {
                    ItemStack armorItem = inventory.getArmorItem(armorSlot);
                    if (!armorItem.isNull()) {

                        playerData.armorItems[armorSlot] = env->NewGlobalRef(armorItem.getObj());
                        env->DeleteLocalRef(armorItem.getObj());
                    }
                }
                env->DeleteLocalRef(inventory.getObj());
            }
        }

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

void ESPModule::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    const auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState) return;

    if (gameState->hasAnyScreen()) return;

    updateMatrices(env);
    collectPlayerData(env);

    if (projectionMatrix.size() != 16 || modelViewMatrix.size() != 16) {
        return;
    }

    setupOpenGL(projectionMatrix, modelViewMatrix);

    const bool render3D = renderMode == 1 || renderMode == 2;
    const bool render2D = renderMode == 0 || renderMode == 2;

    for (const auto& player : players) {
        if (!player.isValid) continue;

        ImColor playerOutlineColor = outline3dColor;
        ImColor playerFillColor = fill3dColor;
        ImColor playerOutline2dCol = outline2dColor;
        ImColor playerFill2dCol = fill2dColor;
        if (player.relation == PlayerRelation::FRIEND) {
            playerOutlineColor = friendColor;
            playerFillColor = friendColor;
            playerOutline2dCol = friendColor;
            playerFill2dCol = friendColor;
        } else if (player.relation == PlayerRelation::NEUTRAL) {
            playerOutlineColor = neutralColor;
            playerFillColor = neutralColor;
            playerOutline2dCol = neutralColor;
            playerFill2dCol = neutralColor;
        }

        if (render3D) {

            if (mode3d == 1 || mode3d == 2) {
                glEnable(GL_BLEND);
                glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

                ImVec4 fillWithOpacity = playerFillColor;
                fillWithOpacity.w = fill3dOpacity;
                setColor(fillWithOpacity);
                drawBox3D(player.boundingBox, true);

                glDepthMask(GL_TRUE);
            }

            if (mode3d == 0 || mode3d == 2) {
                glDisable(GL_DEPTH_TEST);

                glLineWidth(outline3dWidth);
                setColor(playerOutlineColor);
                drawBox3D(player.boundingBox, false);

                glEnable(GL_DEPTH_TEST);
            }
        }

        if (render2D || showHearts || showArmor) {

            Vector3 center(0, 0, 0);
            for (int i = 0; i < 8; i++) {
                center.x += player.boundingBox[i].x;
                center.y += player.boundingBox[i].y;
                center.z += player.boundingBox[i].z;
            }
            center.x /= 8.0f;
            center.y /= 8.0f;
            center.z /= 8.0f;

            float viewX = modelViewMatrix[0]*center.x + modelViewMatrix[4]*center.y +
                          modelViewMatrix[8]*center.z + modelViewMatrix[12];
            float viewY = modelViewMatrix[1]*center.x + modelViewMatrix[5]*center.y +
                          modelViewMatrix[9]*center.z + modelViewMatrix[13];
            float viewZ = modelViewMatrix[2]*center.x + modelViewMatrix[6]*center.y +
                          modelViewMatrix[10]*center.z + modelViewMatrix[14];

            if (viewZ > -1.0f) {
                continue;
            }

            std::vector<Vector2> screenCorners;

            for (int i = 0; i < 8; i++) {
                Vector2 screenPos;
                worldToScreen(player.boundingBox[i], screenPos);
                screenCorners.push_back(screenPos);
            }

            if (screenCorners.size() == 8) {
                float minX = screenCorners[0].x, maxX = screenCorners[0].x;
                float minY = screenCorners[0].y, maxY = screenCorners[0].y;

                for (const auto& corner : screenCorners) {
                    if (corner.x < minX) minX = corner.x;
                    if (corner.x > maxX) maxX = corner.x;
                    if (corner.y < minY) minY = corner.y;
                    if (corner.y > maxY) maxY = corner.y;
                }

                const ImGuiIO& io = GetIO();
                minX = std::max(-io.DisplaySize.x, std::min(minX, io.DisplaySize.x * 2));
                maxX = std::max(-io.DisplaySize.x, std::min(maxX, io.DisplaySize.x * 2));
                minY = std::max(-io.DisplaySize.y, std::min(minY, io.DisplaySize.y * 2));
                maxY = std::max(-io.DisplaySize.y, std::min(maxY, io.DisplaySize.y * 2));

                Vector2 topLeft(minX, minY);
                Vector2 bottomRight(maxX, maxY);

                const float boxWidth = maxX - minX;
                const float boxHeight = maxY - minY;

                float ratio = boxWidth / boxHeight;

                if (boxWidth > 1 && boxHeight > 1) {
                    glMatrixMode(GL_PROJECTION);
                    glPushMatrix();
                    glLoadIdentity();
                    glOrtho(0, io.DisplaySize.x, io.DisplaySize.y, 0, -1, 1);

                    glMatrixMode(GL_MODELVIEW);
                    glPushMatrix();
                    glLoadIdentity();

                    if (render2D) {
                        if (mode2d == 1 || mode2d == 2) {
                            setColor(playerFill2dCol);
                            drawRect2D(topLeft, bottomRight, true);
                        }

                        if (mode2d == 0 || mode2d == 2) {
                            glLineWidth(outline2dWidth);
                            setColor(playerOutline2dCol);
                            drawRect2D(topLeft, bottomRight, false);
                        }

                        if (showHealthBar) {
                            Vector2 healthBarPos(topLeft.x, topLeft.y + boxHeight * 0.5f);
                            drawHealthBar2D(healthBarPos, boxHeight, player.health, player.maxHealth);
                        }
                    }

                    if (showHearts) {
                        drawHearts2D(env, topLeft, boxWidth, boxHeight, player.distance, player.health, player.maxHealth);
                    }

                    if (showArmor) {
                        drawArmor2D(env, topLeft, boxWidth, boxHeight, player.distance, player.armorItems);
                    }

                    glMatrixMode(GL_PROJECTION);
                    glPopMatrix();
                    glMatrixMode(GL_MODELVIEW);
                    glPopMatrix();
                }
            }
        }
    }

    restoreOpenGL();
}

bool ESPModule::worldToScreen(const Vector3& worldPos, Vector2& screenPos) {
    return Render3dBaseModule::worldToScreen(worldPos, screenPos, projectionMatrix, modelViewMatrix);
}

bool ESPModule::updateMatrices(JNIEnv* env) {
    projectionMatrix = ActiveRenderInfo::GetProjectionMatrix(env);
    modelViewMatrix = ActiveRenderInfo::GetModelViewMatrix(env);
    return true;
}

REGISTER_MODULE(ESPModule, ModuleType::ESP)
