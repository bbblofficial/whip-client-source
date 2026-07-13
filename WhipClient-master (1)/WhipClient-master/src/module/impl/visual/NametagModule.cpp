#include "../../../../includes/module/impl/visual/NametagModule.h"
#include "../../../../includes/module/impl/visual/PlayerESPModule.h"

#include <imgui.h>
#include <algorithm>
#include <GL/gl.h>

#include "../../../../includes/bus/EventBus.h"
#include "../../../../includes/util/Debug.h"
#include "../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../includes/wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "../../../../includes/wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../includes/wrapper/minecraft/entity/player/EntityPlayer.h"
#include "../../../../includes/wrapper/java/util/ArrayList.h"
#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../../includes/util/MathUtils.h"
#include "../../../../includes/module/impl/setting/EnemiesModule.h"
#include "../../../../includes/handler/ProviderHandler.h"
#include "../../../../includes/provider/impl/GameStateProvider.h"
#include "../../../../includes/wrapper/minecraft/util/ResourceLocation.h"
#include "../../../../includes/wrapper/minecraft/client/texture/TextureManager.h"
#include "event/sub/RenderNameEvent.h"
#include "handler/ModuleHandler.h"
#include "module/impl/combat/AntiBotModule.h"
#include "gui/includes.h"
#include "imgui_freetype.h"
#include "imgui_impl_opengl3.h"

#include "imgui_impl_opengl2.h"
#include "Poppins-SemiBold.h"

NametagModule::NametagModule(const BindType bindType, const int keyCode)
    : PlayerDataRender3dBaseModule(bindType, keyCode) {

    this->showNames = true;
    this->showHealth = true;
    this->showDistance = true;
    this->showBackground = true;
    this->showHealthBar = false;
    this->showOutline = false;
    this->showEnemiesOnly = false;
    this->nametagScale = 1.0f;
    this->textSize = 20.0f;
    this->outlineThickness = 1.0f;
    this->maxRenderDistance = 64.0f;
    this->healthBarWidth = 50.0f;
    this->healthBarHeight = 4.0f;

    this->nameColor = ImColor(1.0f, 1.0f, 1.0f, 1.0f);
    this->healthColor = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    this->distanceColor = ImColor(0.8f, 0.8f, 0.8f, 1.0f);
    this->backgroundColor = ImColor(0.0f, 0.0f, 0.0f, 0.5f);
    this->healthBarBg = ImColor(0.2f, 0.2f, 0.2f, 0.8f);
    this->healthBarFull = ImColor(0.0f, 1.0f, 0.0f, 1.0f);
    this->healthBarLow = ImColor(1.0f, 0.0f, 0.0f, 1.0f);
    this->outlineColor = ImColor(0.0f, 0.0f, 0.0f, 1.0f);
}

void NametagModule::initializeFonts() {
    if (fontsInitialized) return;

    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig cfg;
    cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_Bitmap;
    cfg.FontDataOwnedByAtlas = false;

    for (float size = 2.0f; size <= 100.0f; size += 2.0f) {
        ImFont* newFont = io.Fonts->AddFontFromMemoryTTF(
            const_cast<void*>(static_cast<const void*>(Poppins_SemiBold_compressed_data.data())),
            static_cast<int>(Poppins_SemiBold_compressed_data.size()),
            size,
            &cfg,
            io.Fonts->GetGlyphRangesCyrillic()
        );

        if (newFont != nullptr) {
            cachedFonts[size] = newFont;
        }
    }

    io.Fonts->Build();
    ImGui_ImplOpenGL2_DestroyFontsTexture();
    ImGui_ImplOpenGL2_CreateFontsTexture();

    fontsInitialized = !cachedFonts.empty();
}

ImFont* NametagModule::getOrCreateFont(float size) {
    if (!fontsInitialized) {
        initializeFonts();
    }

    ImFont* closestFont = nullptr;
    float minDiff = FLT_MAX;

    for (const auto& [cachedSize, cachedFont] : cachedFonts) {
        if (cachedFont != nullptr && cachedFont->ContainerAtlas != nullptr &&
            cachedFont->ContainerAtlas->TexID != nullptr) {
            float diff = std::abs(cachedSize - size);
            if (diff < minDiff) {
                minDiff = diff;
                closestFont = cachedFont;

                if (diff < 1.0f) {
                    return closestFont;
                }
            }
        }
    }

    if (closestFont != nullptr) {
        return closestFont;
    }

    ImGuiIO& io = ImGui::GetIO();
    if (!io.Fonts->Fonts.empty()) {
        return io.Fonts->Fonts[0];
    }

    return nullptr;
}

ImVec4 NametagModule::minecraftColorToImVec4(char code) {
    switch (code) {
        case '0': return ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
        case '1': return ImVec4(0.0f, 0.0f, 0.67f, 1.0f);
        case '2': return ImVec4(0.0f, 0.67f, 0.0f, 1.0f);
        case '3': return ImVec4(0.0f, 0.67f, 0.67f, 1.0f);
        case '4': return ImVec4(0.67f, 0.0f, 0.0f, 1.0f);
        case '5': return ImVec4(0.67f, 0.0f, 0.67f, 1.0f);
        case '6': return ImVec4(1.0f, 0.67f, 0.0f, 1.0f);
        case '7': return ImVec4(0.67f, 0.67f, 0.67f, 1.0f);
        case '8': return ImVec4(0.33f, 0.33f, 0.33f, 1.0f);
        case '9': return ImVec4(0.33f, 0.33f, 1.0f, 1.0f);
        case 'a': return ImVec4(0.33f, 1.0f, 0.33f, 1.0f);
        case 'b': return ImVec4(0.33f, 1.0f, 1.0f, 1.0f);
        case 'c': return ImVec4(1.0f, 0.33f, 0.33f, 1.0f);
        case 'd': return ImVec4(1.0f, 0.33f, 1.0f, 1.0f);
        case 'e': return ImVec4(1.0f, 1.0f, 0.33f, 1.0f);
        case 'f': return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        default:  return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    }
}

std::vector<NametagModule::TextSegment> NametagModule::parseMinecraftText(const std::string& text) {
    std::vector<TextSegment> segments;
    ImVec4 currentColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    std::string currentText;

    for (size_t i = 0; i < text.length(); ++i) {
        unsigned char c = static_cast<unsigned char>(text[i]);

        if ((c == 0xC2 && i + 1 < text.length() && static_cast<unsigned char>(text[i + 1]) == 0xA7)) {

            if (!currentText.empty()) {
                segments.push_back({currentText, currentColor});
                currentText.clear();
            }

            i += 2;

            if (i < text.length()) {
                char colorCode = std::tolower(text[i]);

                if (colorCode == 'r') {
                    currentColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                } else if ((colorCode >= '0' && colorCode <= '9') ||
                          (colorCode >= 'a' && colorCode <= 'f')) {
                    currentColor = minecraftColorToImVec4(colorCode);
                }
            }
        } else if (c == 0xA7) {

            if (!currentText.empty()) {
                segments.push_back({currentText, currentColor});
                currentText.clear();
            }

            i++;

            if (i < text.length()) {
                char colorCode = std::tolower(text[i]);

                if (colorCode == 'r') {
                    currentColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                } else if ((colorCode >= '0' && colorCode <= '9') ||
                          (colorCode >= 'a' && colorCode <= 'f')) {
                    currentColor = minecraftColorToImVec4(colorCode);
                }
            }
        }

        else if (c == 0xE2 && i + 2 < text.length() &&
                 static_cast<unsigned char>(text[i + 1]) == 0x9D &&
                 static_cast<unsigned char>(text[i + 2]) == 0xA4) {
            currentText += '|';
            i += 2;
        }
        else if (c < 32 || c == 127) {

            currentText += '|';
        } else {
            currentText += text[i];
        }
    }

    if (!currentText.empty()) {
        segments.push_back({currentText, currentColor});
    }

    return segments;
}

void NametagModule::drawColoredText(const std::vector<TextSegment>& segments,
                                    const Vector2& pos, float size, bool centered) {
    ImDrawList* drawList = GetBackgroundDrawList();
    const ImFont* fontt = getOrCreateFont(size);
    if (!fontt) return;

    float totalWidth = 0.0f;
    for (const auto& seg : segments) {
        ImVec2 segSize = fontt->CalcTextSizeA(size, FLT_MAX, 0.0f, seg.text.c_str());
        totalWidth += segSize.x;
    }

    float currentX = centered ? (pos.x - totalWidth * 0.5f) : pos.x;

    for (const auto& seg : segments) {

        if (showOutline) {
            for (int x = -1; x <= 1; x++) {
                for (int y = -1; y <= 1; y++) {
                    if (x == 0 && y == 0) continue;
                    draw->text(drawList, fontt, size,
                        ImVec2(currentX + x * outlineThickness, pos.y + y * outlineThickness),
                        draw->get_clr(outlineColor), seg.text.c_str());
                }
            }
        }

        draw->text(drawList, fontt, size, ImVec2(currentX, pos.y),
                   draw->get_clr(seg.color), seg.text.c_str());

        ImVec2 segSize = fontt->CalcTextSizeA(size, FLT_MAX, 0.0f, seg.text.c_str());
        currentX += segSize.x;
    }
}

void NametagModule::collectPlayerData(JNIEnv* env) {
    for (auto& p : players) {
        for (jobject armorItem : p.armorItems) {
            if (armorItem) env->DeleteGlobalRef(armorItem);
        }
        if (p.heldItemRef) env->DeleteGlobalRef(p.heldItemRef);
    }
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

    if (enemiesModule == nullptr) {
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

        if (target.isNull() || localPlayer.entityId() == target.entityId() || target.isDead()) {
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
        playerData.position.y = static_cast<float>(interpY + 2.2f);
        playerData.position.z = static_cast<float>(interpZ);

        playerData.feetPosition.x = static_cast<float>(interpX);
        playerData.feetPosition.y = static_cast<float>(interpY);
        playerData.feetPosition.z = static_cast<float>(interpZ);

        playerData.distance = this->calculateDistance(localPlayerPos, playerData.position);

        if (playerData.distance > maxRenderDistance) {
            env->DeleteLocalRef(entityObj.getObj());
            env->DeleteLocalRef(target.getObj());
            continue;
        }

        playerData.health = target.getHealth();
        playerData.maxHealth = 20.0f;

        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
            IChatComponent chatComponent = target.getFormattedCommandSenderName();
            JavaString javaString = chatComponent.getFormattedText();

            playerData.name = JavaString::jstringToString(env, static_cast<jstring>(javaString.getObj()));
        }
        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
            if (const jstring nameJString = target.getCommandSenderName()) {
                const char* nameChars = env->GetStringUTFChars(nameJString, nullptr);
                playerData.name = std::string(nameChars);
                env->ReleaseStringUTFChars(nameJString, nameChars);
            }
        }

        playerData.isValid = true;
        players.push_back(playerData);

        env->DeleteLocalRef(entityObj.getObj());
        env->DeleteLocalRef(target.getObj());
    }

    env->DeleteLocalRef(mc.getObj());
    env->DeleteLocalRef(world.getObj());
    env->DeleteLocalRef(localPlayer.getObj());
    env->DeleteLocalRef(playerEntities.getObj());
}

void NametagModule::drawTextWithOutline(const char* text, const Vector2& pos, const ImVec4& color, float size, bool centered) {
    ImDrawList* drawList = GetBackgroundDrawList();

    const ImFont* fontt = getOrCreateFont(size);
    if (!fontt) return;

    const ImVec2 textSize = fontt->CalcTextSizeA(size, FLT_MAX, 0.0f, text);
    ImVec2 finalPos;

    if (centered) {
        finalPos = ImVec2(pos.x - textSize.x * 0.5f, pos.y);
    } else {
        finalPos = ImVec2(pos.x, pos.y);
    }

    if (showOutline) {
        for (int x = -1; x <= 1; x++) {
            for (int y = -1; y <= 1; y++) {
                if (x == 0 && y == 0) continue;
                draw->text(drawList, fontt, size,
                    ImVec2(finalPos.x + x * outlineThickness, finalPos.y + y * outlineThickness),
                    draw->get_clr(outlineColor), text);
            }
        }
    }

    draw->text(drawList, fontt, size, finalPos, draw->get_clr(color), text);
}

void NametagModule::drawHealthBar(const Vector2& pos, const float health, float maxHealth, float width, float height) {
    ImDrawList* drawList = GetBackgroundDrawList();

    const float healthPercent = std::max(0.0f, std::min(1.0f, health / maxHealth));
    const ImVec2 barPos(pos.x - width * 0.5f, pos.y);

    draw->rect_filled(
        drawList,
        ImVec2(barPos.x, barPos.y),
        ImVec2(barPos.x + width, barPos.y + height),
        draw->get_clr(healthBarBg)
    );

    const ImVec4 healthBarColor = interpolateColor(healthBarLow, healthBarFull, healthPercent);
    draw->rect_filled(
        drawList,
        ImVec2(barPos.x, barPos.y),
        ImVec2(barPos.x + width * healthPercent, barPos.y + height),
        draw->get_clr(healthBarColor)
    );

    draw->rect(
        drawList,
        ImVec2(barPos.x, barPos.y),
        ImVec2(barPos.x + width, barPos.y + height),
        draw->get_clr(ImVec4(0.0f, 0.0f, 0.0f, 0.8f))
    );
}

void NametagModule::drawHearts2D(const Vector2& center, float scaleFactor,
                                  float health, float maxHealth) {
    if (maxHealth <= 0) return;

    const int maxHearts = static_cast<int>(std::ceil(maxHealth / 2.0f));
    const int currentHealth = static_cast<int>(std::ceil(health));

    const float heartSize = 9.0f * scaleFactor;
    const float heartSpacing = 8.0f * scaleFactor;
    const float totalWidth = maxHearts * heartSpacing;
    const float startX = center.x - totalWidth * 0.5f;
    const float heartsY = center.y;

    constexpr float uScale = 1.0f / 256.0f;
    constexpr float vScale = 1.0f / 256.0f;
    constexpr float uEmpty = 16.0f * uScale;
    constexpr float uFull  = 52.0f * uScale;
    constexpr float uHalf  = 61.0f * uScale;
    constexpr float v0 = 0.0f;
    constexpr float uW = 9.0f * uScale;
    constexpr float vH = 9.0f * vScale;

    glColor4f(1.0f, 1.0f, 1.0f, 1.0f);

    for (int i = 0; i < maxHearts; ++i) {
        const float hX = startX + (i * heartSpacing);

        glBegin(GL_QUADS);
        glTexCoord2f(uEmpty, v0);         glVertex2f(hX, heartsY);
        glTexCoord2f(uEmpty + uW, v0);    glVertex2f(hX + heartSize, heartsY);
        glTexCoord2f(uEmpty + uW, v0+vH); glVertex2f(hX + heartSize, heartsY + heartSize);
        glTexCoord2f(uEmpty, v0 + vH);    glVertex2f(hX, heartsY + heartSize);
        glEnd();

        const int heartValue = (i * 2) + 1;
        if (currentHealth > heartValue) {
            glBegin(GL_QUADS);
            glTexCoord2f(uFull, v0);         glVertex2f(hX, heartsY);
            glTexCoord2f(uFull + uW, v0);    glVertex2f(hX + heartSize, heartsY);
            glTexCoord2f(uFull + uW, v0+vH); glVertex2f(hX + heartSize, heartsY + heartSize);
            glTexCoord2f(uFull, v0 + vH);    glVertex2f(hX, heartsY + heartSize);
            glEnd();
        } else if (currentHealth == heartValue) {
            glBegin(GL_QUADS);
            glTexCoord2f(uHalf, v0);         glVertex2f(hX, heartsY);
            glTexCoord2f(uHalf + uW, v0);    glVertex2f(hX + heartSize, heartsY);
            glTexCoord2f(uHalf + uW, v0+vH); glVertex2f(hX + heartSize, heartsY + heartSize);
            glTexCoord2f(uHalf, v0 + vH);    glVertex2f(hX, heartsY + heartSize);
            glEnd();
        }
    }
}

void NametagModule::drawArmor2D(JNIEnv* env, TextureManager& textureManager,
                                 const Vector2& center, float scaleFactor,
                                 const std::array<jobject, 4>& armorItems) {
    int equippedCount = 0;
    for (jobject item : armorItems) {
        if (item != nullptr) equippedCount++;
    }
    if (equippedCount == 0) return;

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

    const float iconSize = 16.0f * scaleFactor;
    const float spacing = 18.0f * scaleFactor;
    const float totalWidth = equippedCount * spacing;
    float currentX = center.x - totalWidth * 0.5f;
    const float armorY = center.y;

    for (int i = 3; i >= 0; --i) {
        if (armorItems[i] == nullptr) continue;

        ItemStack armorStack(env, armorItems[i]);
        if (armorStack.isNull()) continue;
        armorStack.setDeleteRef(false);

        int itemId = armorStack.getItemId();
        const char* texturePath = getArmorTexturePath(itemId);
        if (!texturePath) { currentX += spacing; continue; }

        ResourceLocation armorTexture(env, texturePath);
        if (armorTexture.isNull()) { currentX += spacing; continue; }

        textureManager.bindTexture(armorTexture);

        glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
        glBegin(GL_QUADS);
        glTexCoord2f(0.0f, 0.0f); glVertex2f(currentX, armorY);
        glTexCoord2f(1.0f, 0.0f); glVertex2f(currentX + iconSize, armorY);
        glTexCoord2f(1.0f, 1.0f); glVertex2f(currentX + iconSize, armorY + iconSize);
        glTexCoord2f(0.0f, 1.0f); glVertex2f(currentX, armorY + iconSize);
        glEnd();

        if (armorStack.isItemEnchanted()) {
            glBlendFunc(GL_SRC_ALPHA, GL_ONE);
            float t = static_cast<float>(GetTickCount() % 2000) / 2000.0f;
            float pulse = 0.3f + 0.15f * std::sin(t * 6.2831853f);
            glColor4f(0.6f, 0.3f, 1.0f, pulse);
            glBegin(GL_QUADS);
            glTexCoord2f(0.0f, 0.0f); glVertex2f(currentX, armorY);
            glTexCoord2f(1.0f, 0.0f); glVertex2f(currentX + iconSize, armorY);
            glTexCoord2f(1.0f, 1.0f); glVertex2f(currentX + iconSize, armorY + iconSize);
            glTexCoord2f(0.0f, 1.0f); glVertex2f(currentX, armorY + iconSize);
            glEnd();
            glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        }

        currentX += spacing;
    }
}

void NametagModule::onRenderName(const RenderNameEvent& event) {
    auto* e = const_cast<RenderNameEvent*>(&event);
    e->setCancelled(true);
}

void NametagModule::onRender3d(const Render3dEvent& event) {
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

    ImDrawList* drawList = GetBackgroundDrawList();
    if (!drawList) return;

    const ImGuiIO& io = GetIO();
    const float screenWidth = io.DisplaySize.x;
    const float screenHeight = io.DisplaySize.y;

    int playerIndex = 0;
    for (const auto& player : players) {
        if (!player.isValid) continue;

        Vector2 screenPos;
        if (!worldToScreen(player.position, screenPos)) continue;

        if (!std::isfinite(screenPos.x) || !std::isfinite(screenPos.y) ||
            screenPos.x < -100 || screenPos.x > screenWidth + 100 ||
            screenPos.y < -100 || screenPos.y > screenHeight + 100) {
            continue;
        }

        Vector2 feetScreenPos{}, headScreenPos{};
        Vector3 headPosition = player.position;
        headPosition.y += 0.3f;

        const bool haveFeet = worldToScreen(player.feetPosition, feetScreenPos)
                           && std::isfinite(feetScreenPos.x) && std::isfinite(feetScreenPos.y);
        const bool haveHead = worldToScreen(headPosition, headScreenPos)
                           && std::isfinite(headScreenPos.x) && std::isfinite(headScreenPos.y);

        float boundingBoxHeight;
        if (haveFeet && haveHead) {
            boundingBoxHeight = std::abs(headScreenPos.y - feetScreenPos.y);
        } else {

            const float d = std::max(player.distance, 0.5f);
            boundingBoxHeight = std::clamp(1.8f / d * screenHeight * 0.7f,
                                           50.0f, screenHeight * 0.9f);
        }
        const float scaledProjection = std::clamp(boundingBoxHeight / (0.33038348082f * screenHeight), 0.0f, 1.0f);
        float scaleFactor = scaledProjection;

        if (scaleFactor < 0.2f) {
            scaleFactor = 0.2f;
        }

        const float scaledTextSize = textSize * nametagScale * scaleFactor;

        if (scaledTextSize <= 0 || scaledTextSize > 200 || !std::isfinite(scaledTextSize)) {
            continue;
        }

        std::vector<TextSegment> segments;

        if (showHealth) {
            char healthStr[16];
            snprintf(healthStr, sizeof(healthStr), "%.0f ", player.health);
            float healthPercent = std::max(0.0f, std::min(1.0f, player.health / player.maxHealth));
            ImVec4 currentHealthColor = interpolateColor(healthBarLow, healthBarFull, healthPercent);
            segments.push_back({std::string(healthStr), currentHealthColor});
        }

        if (showNames) {
            auto nameSegments = parseMinecraftText(player.name);
            if (player.relation == PlayerRelation::FRIEND) {
                for (auto& seg : nameSegments) seg.color = friendColor.Value;
            } else if (player.relation == PlayerRelation::ENEMY) {
                for (auto& seg : nameSegments) seg.color = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
            }
            segments.insert(segments.end(), nameSegments.begin(), nameSegments.end());
        }

        if (showDistance) {
            char distStr[16];
            snprintf(distStr, sizeof(distStr), " %.0fm", player.distance);
            segments.push_back({std::string(distStr), distanceColor});
        }

        const ImFont* fontt = getOrCreateFont(textSize);
        if (!fontt) continue;

        float totalWidth = 0.0f;
        for (const auto& seg : segments) {
            ImVec2 segSize = fontt->CalcTextSizeA(scaledTextSize, FLT_MAX, 0.0f, seg.text.c_str());
            totalWidth += segSize.x;
        }

        if (showBackground) {
            const float padding = 4.0f;
            const float halfW = totalWidth * 0.5f + padding;
            bool hasContentAbove = false;
            {
                auto* espMod = PlayerESPModule::getInstancePtr();
                if (espMod && espMod->isEnabled()) {
                    auto it = PlayerESPModule::sharedBlockW.find(player.entityId);
                    if (it != PlayerESPModule::sharedBlockW.end() && it->second > 0.0f) {
                        hasContentAbove = true;
                    }
                }
            }
            const ImVec2 bgMin(screenPos.x - halfW, screenPos.y - padding);
            const ImVec2 bgMax(screenPos.x + halfW, screenPos.y + scaledTextSize + padding);

            const ImU32 bgCol = hasContentAbove
                ? IM_COL32(0, 0, 0, 178)
                : draw->get_clr(backgroundColor);
            draw->rect_filled(drawList, bgMin, bgMax, bgCol, 3.0f,
                              draw_flags_round_corners_all);

            ImColor relationCol = nameColor;
            if (player.relation == PlayerRelation::FRIEND) relationCol = friendColor;
            else if (player.relation == PlayerRelation::NEUTRAL) relationCol = neutralColor;
            else if (player.relation == PlayerRelation::ENEMY) relationCol = ImColor(1.0f, 0.0f, 0.0f, 1.0f);

            drawList->AddLine(
                ImVec2(bgMin.x + 4.0f, bgMax.y - 1.5f),
                ImVec2(bgMax.x - 4.0f, bgMax.y - 1.5f),
                ImGui::ColorConvertFloat4ToU32(relationCol.Value), 1.0f);
        }

        drawColoredText(segments, screenPos, scaledTextSize, true);

        playerIndex++;
    }
}

void NametagModule::registerEvents() {
    PlayerDataRender3dBaseModule<NametagModule, ModuleType::NAMETAG, CategoryType::VISUAL>::registerEvents();

    EventBus::getInstance().subscribe<RenderNameEvent>(
    this,
    [this](const RenderNameEvent& event) {
        if (this->isEnabled()) {
            this->onRenderName(event);
        }
    },
    EventPriority::HIGH,
    false
);
}

bool NametagModule::worldToScreen(const Vector3& worldPos, Vector2& screenPos) {
    return Render3dBaseModule::worldToScreen(worldPos, screenPos, projectionMatrix, modelViewMatrix);
}

bool NametagModule::updateMatrices(JNIEnv* env) {
    projectionMatrix = ActiveRenderInfo::GetProjectionMatrix(env);
    modelViewMatrix = ActiveRenderInfo::GetModelViewMatrix(env);
    return true;
}

REGISTER_MODULE(NametagModule, ModuleType::NAMETAG)
