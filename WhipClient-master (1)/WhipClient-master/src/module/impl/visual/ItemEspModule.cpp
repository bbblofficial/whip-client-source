#include "module/impl/visual/ItemEspModule.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "wrapper/minecraft/entity/render/RenderManager.h"
#include "wrapper/minecraft/entity/Entity.h"
#include "wrapper/minecraft/entity/item/EntityItem.h"
#include "wrapper/minecraft/item/ItemStack.h"
#include "wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo.h"
#include "wrapper/java/util/ArrayList.h"
#include "handler/ProviderHandler.h"
#include "provider/impl/GameStateProvider.h"

#include <windows.h>
#include <gl/GL.h>
#include <cmath>
#include <string>

ItemEspModule::ItemEspModule(BindType bindType, int keyCode)
    : Render3dBaseModule(bindType, keyCode) {}

void ItemEspModule::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    const auto* gameState = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gameState) return;
    if (gameState->hasAnyScreen()) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    WorldClient world = mc.theWorld();
    EntityClientPlayerMP lp = mc.thePlayer();
    if (world.isNull() || lp.isNull()) return;

    bool is18 = MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9;
    Vec3D renderPos;
    if (is18) {
        RenderManager rm = mc.getRenderManager();
        if (!rm.isNull()) { renderPos = rm.getRenderPos(); env->DeleteLocalRef(rm.getObj()); }
    } else {
        RenderManager rm = RenderManager::getInstance(env);
        if (!rm.isNull()) { renderPos = rm.getRenderPos(); env->DeleteLocalRef(rm.getObj()); }
    }

    float pt = mc.timer().GetrenderPartialTicks();
    double lpX = lp.posX(), lpY = lp.posY(), lpZ = lp.posZ();

    std::vector<float> projMatrix = ActiveRenderInfo::GetProjectionMatrix(env);
    std::vector<float> mvMatrix = ActiveRenderInfo::GetModelViewMatrix(env);
    if (projMatrix.size() != 16 || mvMatrix.size() != 16) return;

    setupOpenGL(projMatrix, mvMatrix);

    ArrayList entityList = world.loadedEntityList();
    if (entityList.isNull()) { restoreOpenGL(); return; }

    int count = entityList.size();
    for (int i = 0; i < count && i < 500; i++) {
        if (env->PushLocalFrame(8) < 0) break;

        JavaObject rawObj = entityList.get(i);
        if (rawObj.isNull()) { env->PopLocalFrame(nullptr); continue; }

        if (!EntityItem::isInstance(env, rawObj.getObj())) { env->PopLocalFrame(nullptr); continue; }

        Entity ent(env, rawObj.getObj());
        ent.setDeleteRef(false);

        double ex = ent.lastTickPosX() + (ent.posX() - ent.lastTickPosX()) * pt;
        double ey = ent.lastTickPosY() + (ent.posY() - ent.lastTickPosY()) * pt;
        double ez = ent.lastTickPosZ() + (ent.posZ() - ent.lastTickPosZ()) * pt;

        double dx = lpX - ex, dy = lpY - ey, dz = lpZ - ez;
        float dist = static_cast<float>(std::sqrt(dx*dx + dy*dy + dz*dz));
        if (dist > maxDistance) { env->PopLocalFrame(nullptr); continue; }

        float rx = static_cast<float>(ex - renderPos.x);
        float ry = static_cast<float>(ey - renderPos.y);
        float rz = static_cast<float>(ez - renderPos.z);

        constexpr float hw = 0.15f, h = 0.25f;
        Vector3 box[8] = {
            {rx-hw, ry,   rz-hw}, {rx+hw, ry,   rz-hw},
            {rx+hw, ry,   rz+hw}, {rx-hw, ry,   rz+hw},
            {rx-hw, ry+h, rz-hw}, {rx+hw, ry+h, rz-hw},
            {rx+hw, ry+h, rz+hw}, {rx-hw, ry+h, rz+hw}
        };

        glDisable(GL_DEPTH_TEST);
        glLineWidth(1.5f);
        setColor(itemColor);
        drawBox3D(box, false);

        ImVec4 fillCol = itemColor;
        fillCol.w *= 0.25f;
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        setColor(fillCol);
        drawBox3D(box, true);
        glEnable(GL_DEPTH_TEST);

        Vector3 namePos = {rx, ry + h + 0.1f, rz};
        Vector2 screenPos;
        if (worldToScreen(namePos, screenPos, projMatrix, mvMatrix)) {
            ImDrawList* dl = ImGui::GetBackgroundDrawList();
            if (dl) {
                std::string itemName;
                {
                    EntityItem entItem(env, rawObj.getObj());
                    entItem.setDeleteRef(false);
                    ItemStack stack = entItem.getEntityItem();
                    if (!stack.isNull()) {
                        stack.setDeleteRef(false);
                        jstring displayName = stack.getDisplayName();
                        if (displayName) {
                            const char* c = env->GetStringUTFChars(displayName, nullptr);
                            if (c) {
                                itemName = c;
                                env->ReleaseStringUTFChars(displayName, c);
                            }
                            env->DeleteLocalRef(displayName);
                        }
                        env->DeleteLocalRef(stack.getObj());
                    }
                    if (env->ExceptionCheck()) env->ExceptionClear();
                }

                if (!itemName.empty()) {
                    char label[128];
                    snprintf(label, sizeof(label), "%s [%.0fm]", itemName.c_str(), dist);
                    ImVec2 textSz = ImGui::CalcTextSize(label);
                    float tx = screenPos.x - textSz.x * 0.5f;
                    float ty = screenPos.y - textSz.y;

                    dl->AddRectFilled(
                        ImVec2(tx - 2, ty - 1),
                        ImVec2(tx + textSz.x + 2, ty + textSz.y + 1),
                        IM_COL32(0, 0, 0, 140), 2.0f);
                    dl->AddText(ImVec2(tx, ty),
                        ImGui::ColorConvertFloat4ToU32(itemColor.Value), label);
                }
            }
        }

        env->PopLocalFrame(nullptr);
    }
    env->DeleteLocalRef(entityList.getObj());

    restoreOpenGL();
}

REGISTER_MODULE(ItemEspModule, ModuleType::ITEM_ESP)
