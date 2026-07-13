#include "module/impl/visual/StorageEsp.h"

#include <imgui.h>
#include <widgets.h>
#include <algorithm>
#include <GL/gl.h>

#include "util/ClientStrings.h"
#include "../../../../includes/bus/EventBus.h"
#include "../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../includes/wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "../../../../includes/wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../includes/wrapper/minecraft/tileentity/TileEntity.h"
#include "../../../../includes/wrapper/java/util/ArrayList.h"
#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../../includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo.h"
#include "../../../../includes/util/MathUtils.h"
#include "../../../../includes/handler/ProviderHandler.h"
#include "../../../../includes/provider/impl/GameStateProvider.h"
#include "event/sub/RenderWorldEvent.h"
#include "handler/ModuleHandler.h"

StorageESPModule::StorageESPModule(const BindType bindType, const int keyCode)
    : PlayerDataRender3dBaseModule(bindType, keyCode) {

    this->renderMode = 2;
    this->mode3d = 0;
    this->mode2d = 2;

    this->selectedStorageTypes = {true, true, true, true, true, true, true};

    this->maxRenderDistance = 256.0f;

    this->chestColor = ImColor(1.0f, 0.84f, 0.0f, 1.0f);
    this->enderChestColor = ImColor(0.5f, 0.0f, 0.5f, 1.0f);
    this->trappedChestColor = ImColor(1.0f, 0.0f, 0.0f, 1.0f);
    this->furnaceColor = ImColor(0.5f, 0.5f, 0.5f, 1.0f);
    this->dispenserColor = ImColor(0.3f, 0.3f, 0.3f, 1.0f);
    this->dropperColor = ImColor(0.4f, 0.4f, 0.4f, 1.0f);
    this->hopperColor = ImColor(0.2f, 0.2f, 0.2f, 1.0f);

    this->outline3dWidth = 2.0f;
    this->outline2dWidth = 1.5f;
    this->fillAlpha3d = 0.15f;
    this->fillAlpha2d = 0.25f;

    this->showLabels = false;
    this->labelColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);
    this->labelScale = 1.0f;
}

ImColor StorageESPModule::getStorageColor(const std::string& type) {
    if (type == Strings::storageChestLower()) return chestColor;
    if (type == Strings::storageEnderChestLower()) return enderChestColor;
    if (type == Strings::storageTrappedChestLower()) return trappedChestColor;
    if (type == Strings::storageFurnaceLower()) return furnaceColor;
    if (type == Strings::storageDispenserLower()) return dispenserColor;
    if (type == Strings::storageDropperLower()) return dropperColor;
    if (type == Strings::storageHopperLower()) return hopperColor;
    return ImColor(1.0f, 1.0f, 1.0f, 1.0f);
}

std::string StorageESPModule::getStorageLabel(const std::string& type) {
    if (type == Strings::storageChestLower()) return Strings::storageChest();
    if (type == Strings::storageEnderChestLower()) return Strings::storageEnderChest();
    if (type == Strings::storageTrappedChestLower()) return Strings::storageTrappedChest();
    if (type == Strings::storageFurnaceLower()) return Strings::storageFurnace();
    if (type == Strings::storageDispenserLower()) return Strings::storageDispenser();
    if (type == Strings::storageDropperLower()) return Strings::storageDropper();
    if (type == Strings::storageHopperLower()) return Strings::storageHopper();
    return Strings::storageGeneric();
}

bool StorageESPModule::isStorageTypeEnabled(const std::string& type) {

    if (selectedStorageTypes.size() < 7) return false;

    if (type == Strings::storageChestLower()) return selectedStorageTypes[0];
    if (type == Strings::storageEnderChestLower()) return selectedStorageTypes[1];
    if (type == Strings::storageTrappedChestLower()) return selectedStorageTypes[2];
    if (type == Strings::storageFurnaceLower()) return selectedStorageTypes[3];
    if (type == Strings::storageDispenserLower()) return selectedStorageTypes[4];
    if (type == Strings::storageDropperLower()) return selectedStorageTypes[5];
    if (type == Strings::storageHopperLower()) return selectedStorageTypes[6];
    return false;
}

void StorageESPModule::collectPlayerData(JNIEnv* env) {
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

    ArrayList loadedTileEntities = world.loadedTileEntityList();
    if (loadedTileEntities.isNull()) {
        env->DeleteLocalRef(mc.getObj());
        env->DeleteLocalRef(world.getObj());
        env->DeleteLocalRef(localPlayer.getObj());
        return;
    }

    const int size = loadedTileEntities.size();

    for (int i = 0; i < size; i++) {
        JavaObject tileEntityObj = loadedTileEntities.get(i);
        auto tileEntity = tileEntityObj.convertTo<TileEntity>();

        if (tileEntity.isNull()) {
            env->DeleteLocalRef(tileEntityObj.getObj());
            env->DeleteLocalRef(tileEntity.getObj());
            continue;
        }

        std::string entityType;

        if (tileEntity.isInstanceOf(Strings::tileEntityChest()) && isStorageTypeEnabled(Strings::storageChestLower())) {
            entityType = Strings::storageChestLower();
        } else if (tileEntity.isInstanceOf(Strings::tileEntityEnderChest()) && isStorageTypeEnabled(Strings::storageEnderChestLower())) {
            entityType = Strings::storageEnderChestLower();
        } else if (tileEntity.isInstanceOf(Strings::tileEntityFurnace()) && isStorageTypeEnabled(Strings::storageFurnaceLower())) {
            entityType = Strings::storageFurnaceLower();
        } else if (tileEntity.isInstanceOf(Strings::tileEntityDispenser()) && isStorageTypeEnabled(Strings::storageDispenserLower())) {
            entityType = Strings::storageDispenserLower();
        } else if (tileEntity.isInstanceOf(Strings::tileEntityDropper()) && isStorageTypeEnabled(Strings::storageDropperLower())) {
            entityType = Strings::storageDropperLower();
        } else if (tileEntity.isInstanceOf(Strings::tileEntityHopper()) && isStorageTypeEnabled(Strings::storageHopperLower())) {
            entityType = Strings::storageHopperLower();
        } else {
            env->DeleteLocalRef(tileEntityObj.getObj());
            env->DeleteLocalRef(tileEntity.getObj());
            continue;
        }

        PlayerData storageData;
         int posX;
         int posY;
         int posZ;

        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
            posX = tileEntity.getX();
            posY = tileEntity.getY();
            posZ = tileEntity.getZ();
        } else {
            posX = tileEntity.getPos().getX();
            posY = tileEntity.getPos().getY();
            posZ = tileEntity.getPos().getZ();
        }

        Vector3 blockPos;
        blockPos.x = static_cast<float>(posX - renderPos.x);
        blockPos.y = static_cast<float>(posY - renderPos.y);
        blockPos.z = static_cast<float>(posZ - renderPos.z);

        storageData.position.x = static_cast<float>(posX + 0.5 - renderPos.x);
        storageData.position.y = static_cast<float>(posY + 0.5 - renderPos.y);
        storageData.position.z = static_cast<float>(posZ + 0.5 - renderPos.z);

        storageData.name = getStorageLabel(entityType);
        storageData.isValid = true;

        storageData.health = 0.0f;
        storageData.maxHealth = 0.0f;

        storageData.boundingBox[0] = Vector3(blockPos.x, blockPos.y, blockPos.z);
        storageData.boundingBox[1] = Vector3(blockPos.x + 1, blockPos.y, blockPos.z);
        storageData.boundingBox[2] = Vector3(blockPos.x + 1, blockPos.y, blockPos.z + 1);
        storageData.boundingBox[3] = Vector3(blockPos.x, blockPos.y, blockPos.z + 1);
        storageData.boundingBox[4] = Vector3(blockPos.x, blockPos.y + 1, blockPos.z);
        storageData.boundingBox[5] = Vector3(blockPos.x + 1, blockPos.y + 1, blockPos.z);
        storageData.boundingBox[6] = Vector3(blockPos.x + 1, blockPos.y + 1, blockPos.z + 1);
        storageData.boundingBox[7] = Vector3(blockPos.x, blockPos.y + 1, blockPos.z + 1);

        players.push_back(storageData);

        env->DeleteLocalRef(tileEntityObj.getObj());
        env->DeleteLocalRef(tileEntity.getObj());
    }

    env->DeleteLocalRef(mc.getObj());
    env->DeleteLocalRef(world.getObj());
    env->DeleteLocalRef(localPlayer.getObj());
    env->DeleteLocalRef(loadedTileEntities.getObj());
}

void StorageESPModule::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState) return;

    if (!gameState->inGameHasFocus()) return;
    if (gameState->isChestOpen()) return;
    if (gameState->isOptionsOpen()) return;
    if (gameState->isInventoryOpen()) return;

    updateMatrices(env);
    collectPlayerData(env);

    if (projectionMatrix.size() != 16 || modelViewMatrix.size() != 16) {
        return;
    }

    setupOpenGL(projectionMatrix, modelViewMatrix);

    const bool render3D = renderMode == 1 || renderMode == 2;
    const bool render2D = renderMode == 0 || renderMode == 2;

    for (const auto& storage : players) {
        if (!storage.isValid) continue;

        ImColor storageColor = chestColor;
        if (storage.name == Strings::storageEnderChest()) storageColor = enderChestColor;
        else if (storage.name == Strings::storageTrappedChest()) storageColor = trappedChestColor;
        else if (storage.name == Strings::storageFurnace()) storageColor = furnaceColor;
        else if (storage.name == Strings::storageDispenser()) storageColor = dispenserColor;
        else if (storage.name == Strings::storageDropper()) storageColor = dropperColor;
        else if (storage.name == Strings::storageHopper()) storageColor = hopperColor;

        if (render3D) {

            if (mode3d == 1 || mode3d == 2) {
                glEnable(GL_BLEND);
                glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

                ImVec4 fillColor = storageColor;
                fillColor.w = fillAlpha3d;
                setColor(fillColor);
                drawBox3D(storage.boundingBox, true);

                glDepthMask(GL_TRUE);
            }

            if (mode3d == 0 || mode3d == 2) {
                glDisable(GL_DEPTH_TEST);

                glLineWidth(outline3dWidth);
                setColor(storageColor);
                drawBox3D(storage.boundingBox, false);

                glEnable(GL_DEPTH_TEST);
            }
        }

        if (render2D) {
            std::vector<Vector2> screenCorners;

            for (int i = 0; i < 8; i++) {
                Vector2 screenPos;
                if (worldToScreen(storage.boundingBox[i], screenPos)) {
                    screenCorners.push_back(screenPos);
                }
            }

            if (screenCorners.size() >= 2) {
                float minX = screenCorners[0].x, maxX = screenCorners[0].x;
                float minY = screenCorners[0].y, maxY = screenCorners[0].y;

                for (const auto& corner : screenCorners) {
                    if (corner.x < minX) minX = corner.x;
                    if (corner.x > maxX) maxX = corner.x;
                    if (corner.y < minY) minY = corner.y;
                    if (corner.y > maxY) maxY = corner.y;
                }

                const ImGuiIO& io = ImGui::GetIO();
                minX = std::max(0.0f, std::min(minX, io.DisplaySize.x));
                maxX = std::max(0.0f, std::min(maxX, io.DisplaySize.x));
                minY = std::max(0.0f, std::min(minY, io.DisplaySize.y));
                maxY = std::max(0.0f, std::min(maxY, io.DisplaySize.y));

                Vector2 topLeft(minX, minY);
                Vector2 bottomRight(maxX, maxY);

                const float boxWidth = maxX - minX;
                const float boxHeight = maxY - minY;

                if (boxWidth > 3 && boxHeight > 3) {
                    glMatrixMode(GL_PROJECTION);
                    glPushMatrix();
                    glLoadIdentity();
                    const ImGuiIO& io = ImGui::GetIO();
                    glOrtho(0, io.DisplaySize.x, io.DisplaySize.y, 0, -1, 1);

                    glMatrixMode(GL_MODELVIEW);
                    glPushMatrix();
                    glLoadIdentity();

                    if (mode2d == 1 || mode2d == 2) {
                        ImVec4 fillColor = storageColor;
                        fillColor.w = fillAlpha2d;
                        setColor(fillColor);
                        drawRect2D(topLeft, bottomRight, true);
                    }

                    if (mode2d == 0 || mode2d == 2) {
                        glLineWidth(outline2dWidth);
                        setColor(storageColor);
                        drawRect2D(topLeft, bottomRight, false);
                    }

                    if (showLabels) {
                        const ImVec2 textSize = ImGui::CalcTextSize(storage.name.c_str());
                        Vector2 labelPos(topLeft.x + boxWidth * 0.5f - textSize.x * labelScale * 0.5f, topLeft.y - 15.0f * labelScale);

                        ImGui::GetBackgroundDrawList()->AddText(
                            ImGui::GetFont(),
                            13.0f * labelScale,
                            ImVec2(labelPos.x + 1, labelPos.y + 1),
                            ImColor(0.0f, 0.0f, 0.0f, 0.8f),
                            storage.name.c_str()
                        );

                        ImGui::GetBackgroundDrawList()->AddText(
                            ImGui::GetFont(),
                            13.0f * labelScale,
                            ImVec2(labelPos.x, labelPos.y),
                            labelColor,
                            storage.name.c_str()
                        );
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

bool StorageESPModule::worldToScreen(const Vector3& worldPos, Vector2& screenPos) {
    return Render3dBaseModule::worldToScreen(worldPos, screenPos, projectionMatrix, modelViewMatrix);
}

bool StorageESPModule::updateMatrices(JNIEnv* env) {
    projectionMatrix = ActiveRenderInfo::GetProjectionMatrix(env);
    modelViewMatrix = ActiveRenderInfo::GetModelViewMatrix(env);
    return true;
}

REGISTER_MODULE(StorageESPModule, ModuleType::STORAGE_ESP)
