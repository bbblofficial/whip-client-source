#include "../../../../includes/module/impl/visual/PlayerESPModule.h"
#include "wrapper/minecraft/client/settings/GameSettings.h"
#include "wrapper/minecraft/client/renderer/GlStateManager.h"

#include <imgui.h>
#include <algorithm>
#include <cmath>
#include <GL/gl.h>

#ifndef GL_COMBINE
#define GL_COMBINE 0x8570
#endif
#ifndef GL_COMBINE_RGB
#define GL_COMBINE_RGB 0x8571
#endif
#ifndef GL_COMBINE_ALPHA
#define GL_COMBINE_ALPHA 0x8572
#endif
#ifndef GL_SOURCE0_RGB
#define GL_SOURCE0_RGB 0x8580
#endif
#ifndef GL_SOURCE0_ALPHA
#define GL_SOURCE0_ALPHA 0x8588
#endif
#ifndef GL_SOURCE1_ALPHA
#define GL_SOURCE1_ALPHA 0x8589
#endif
#ifndef GL_CONSTANT_TEX
#define GL_CONSTANT_TEX 0x8576
#endif
#ifndef GL_TEXTURE_ENV_COLOR
#define GL_TEXTURE_ENV_COLOR 0x2201
#endif

#ifndef GL_FRAMEBUFFER
#define GL_FRAMEBUFFER           0x8D40
#define GL_COLOR_ATTACHMENT0     0x8CE0
#define GL_FRAMEBUFFER_COMPLETE  0x8CD5
#define GL_FRAMEBUFFER_BINDING   0x8CA6
#endif
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE         0x812F
#endif

#include "../../../../includes/bus/EventBus.h"
#include "../../../../includes/wrapper/minecraft/client/Minecraft.h"
#include "../../../../includes/wrapper/minecraft/client/multiplayer/WorldClient.h"
#include "../../../../includes/wrapper/minecraft/client/entity/EntityClientPlayerMP.h"
#include "../../../../includes/wrapper/minecraft/entity/render/RenderManager.h"
#include "../../../../includes/wrapper/minecraft/entity/player/EntityPlayer.h"
#include "../../../../includes/wrapper/java/util/ArrayList.h"
#include "../../../../includes/wrapper/primitive/JavaObject.h"
#include "../../../../includes/handler/ProviderHandler.h"
#include "../../../../includes/handler/MappingHandler.h"
#include "../../../../includes/provider/impl/GameStateProvider.h"
#include "../../../../includes/wrapper/minecraft/enchantment/EnchantmentHelper.h"
#include "../../../../includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo.h"
#include "../../../../includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h"
#include "../../../../includes/wrapper/minecraft/util/ResourceLocation.h"
#include "../../../../includes/wrapper/minecraft/client/texture/TextureManager.h"
#include "handler/ModuleHandler.h"
#include "module/impl/visual/NametagModule.h"
#include "module/impl/combat/AntiBotModule.h"
#include "gui/includes.h"
#include "imgui_freetype.h"
#include "imgui_impl_opengl2.h"
#include "Poppins-SemiBold.h"

#ifndef GL_RENDERBUFFER
#define GL_RENDERBUFFER      0x8D41
#define GL_DEPTH_ATTACHMENT  0x8D00
#define GL_DEPTH_COMPONENT24 0x81A6
#endif

namespace {
    using PFN_glGenFBs    = void   (WINAPI*)(GLsizei, GLuint*);
    using PFN_glDelFBs    = void   (WINAPI*)(GLsizei, const GLuint*);
    using PFN_glBindFB    = void   (WINAPI*)(GLenum, GLuint);
    using PFN_glFBTex2D   = void   (WINAPI*)(GLenum, GLenum, GLenum, GLuint, GLint);
    using PFN_glFBStatus  = GLenum (WINAPI*)(GLenum);
    using PFN_glGenRBs    = void   (WINAPI*)(GLsizei, GLuint*);
    using PFN_glDelRBs    = void   (WINAPI*)(GLsizei, const GLuint*);
    using PFN_glBindRB    = void   (WINAPI*)(GLenum, GLuint);
    using PFN_glRBStore   = void   (WINAPI*)(GLenum, GLenum, GLsizei, GLsizei);
    using PFN_glFBRB      = void   (WINAPI*)(GLenum, GLenum, GLenum, GLuint);

    PFN_glGenFBs   s_glGenFBs   = nullptr;
    PFN_glDelFBs   s_glDelFBs   = nullptr;
    PFN_glBindFB   s_glBindFB   = nullptr;
    PFN_glFBTex2D  s_glFBTex2D  = nullptr;
    PFN_glFBStatus s_glFBStatus = nullptr;
    PFN_glGenRBs   s_glGenRBs   = nullptr;
    PFN_glDelRBs   s_glDelRBs   = nullptr;
    PFN_glBindRB   s_glBindRB   = nullptr;
    PFN_glRBStore  s_glRBStore  = nullptr;
    PFN_glFBRB     s_glFBRB     = nullptr;
    bool s_fboFuncInit = false;
    bool s_fboFuncOk   = false;

    void* glext(const char* core, const char* ext) {
        void* p = reinterpret_cast<void*>(wglGetProcAddress(core));
        if (!p) p = reinterpret_cast<void*>(wglGetProcAddress(ext));
        if (!p) {
            if (HMODULE m = GetModuleHandleA("opengl32.dll"))
                p = reinterpret_cast<void*>(GetProcAddress(m, core));
        }
        return p;
    }

    void initFBOFuncs() {
        if (s_fboFuncInit) return;
        s_fboFuncInit = true;
        s_glGenFBs   = reinterpret_cast<PFN_glGenFBs>  (glext("glGenFramebuffers",        "glGenFramebuffersEXT"));
        s_glDelFBs   = reinterpret_cast<PFN_glDelFBs>  (glext("glDeleteFramebuffers",     "glDeleteFramebuffersEXT"));
        s_glBindFB   = reinterpret_cast<PFN_glBindFB>  (glext("glBindFramebuffer",        "glBindFramebufferEXT"));
        s_glFBTex2D  = reinterpret_cast<PFN_glFBTex2D> (glext("glFramebufferTexture2D",   "glFramebufferTexture2DEXT"));
        s_glFBStatus = reinterpret_cast<PFN_glFBStatus>(glext("glCheckFramebufferStatus", "glCheckFramebufferStatusEXT"));
        s_glGenRBs   = reinterpret_cast<PFN_glGenRBs>  (glext("glGenRenderbuffers",       "glGenRenderbuffersEXT"));
        s_glDelRBs   = reinterpret_cast<PFN_glDelRBs>  (glext("glDeleteRenderbuffers",    "glDeleteRenderbuffersEXT"));
        s_glBindRB   = reinterpret_cast<PFN_glBindRB>  (glext("glBindRenderbuffer",       "glBindRenderbufferEXT"));
        s_glRBStore  = reinterpret_cast<PFN_glRBStore> (glext("glRenderbufferStorage",    "glRenderbufferStorageEXT"));
        s_glFBRB     = reinterpret_cast<PFN_glFBRB>    (glext("glFramebufferRenderbuffer","glFramebufferRenderbufferEXT"));
        s_fboFuncOk  = s_glGenFBs && s_glDelFBs && s_glBindFB && s_glFBTex2D && s_glFBStatus
                    && s_glGenRBs && s_glDelRBs && s_glBindRB && s_glRBStore  && s_glFBRB;
    }

    struct GlowFBO {
        GLuint fbo = 0, tex = 0, depthRB = 0;
        int    w   = 0, h   = 0;

        void destroy() {
            if (tex)                      { glDeleteTextures(1, &tex); tex = 0; }
            if (depthRB && s_glDelRBs)    { s_glDelRBs(1, &depthRB);   depthRB = 0; }
            if (fbo && s_glDelFBs)        { s_glDelFBs(1, &fbo);       fbo = 0; }
            w = h = 0;
        }

        bool ensure(int width, int height, bool withDepth) {
            if (w == width && h == height && fbo && tex
                && ((depthRB != 0) == withDepth)) return true;
            if (!s_fboFuncOk) return false;
            destroy();
            glGenTextures(1, &tex);
            glBindTexture(GL_TEXTURE_2D, tex);
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,     GL_CLAMP_TO_EDGE);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,     GL_CLAMP_TO_EDGE);
            glBindTexture(GL_TEXTURE_2D, 0);
            s_glGenFBs(1, &fbo);
            s_glBindFB(GL_FRAMEBUFFER, fbo);
            s_glFBTex2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tex, 0);
            if (withDepth) {
                s_glGenRBs(1, &depthRB);
                s_glBindRB(GL_RENDERBUFFER, depthRB);
                s_glRBStore(GL_RENDERBUFFER, GL_DEPTH_COMPONENT24, width, height);
                s_glFBRB(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_RENDERBUFFER, depthRB);
                s_glBindRB(GL_RENDERBUFFER, 0);
            }
            const GLenum st = s_glFBStatus(GL_FRAMEBUFFER);
            s_glBindFB(GL_FRAMEBUFFER, 0);
            if (st != GL_FRAMEBUFFER_COMPLETE) { destroy(); return false; }
            w = width; h = height;
            return true;
        }
    };
    GlowFBO s_pingFBO, s_pongFBO;

    void kawasePass(GLuint srcTex, int vpW, int vpH, float d) {
        glClearColor(0.f, 0.f, 0.f, 0.f);
        glClear(GL_COLOR_BUFFER_BIT);

        glDisable(GL_DEPTH_TEST);
        glDepthMask(GL_FALSE);
        glEnable(GL_BLEND);
        glBlendFunc(GL_ONE, GL_ONE);
        glEnable(GL_TEXTURE_2D);
        glBindTexture(GL_TEXTURE_2D, srcTex);
        glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);

        glMatrixMode(GL_PROJECTION); glPushMatrix(); glLoadIdentity();
        glOrtho(0.0, 1.0, 0.0, 1.0, -1.0, 1.0);
        glMatrixMode(GL_MODELVIEW);  glPushMatrix(); glLoadIdentity();

        const float du = d / static_cast<float>(vpW);
        const float dv = d / static_cast<float>(vpH);
        glColor4f(0.25f, 0.25f, 0.25f, 0.25f);
        const float taps[4][2] = {{du, dv}, {-du, dv}, {du, -dv}, {-du, -dv}};
        for (const auto& t : taps) {
            glBegin(GL_QUADS);
                glTexCoord2f(0.f + t[0], 0.f + t[1]); glVertex2f(0.f, 0.f);
                glTexCoord2f(1.f + t[0], 0.f + t[1]); glVertex2f(1.f, 0.f);
                glTexCoord2f(1.f + t[0], 1.f + t[1]); glVertex2f(1.f, 1.f);
                glTexCoord2f(0.f + t[0], 1.f + t[1]); glVertex2f(0.f, 1.f);
            glEnd();
        }

        glBindTexture(GL_TEXTURE_2D, 0);
        glMatrixMode(GL_MODELVIEW);  glPopMatrix();
        glMatrixMode(GL_PROJECTION); glPopMatrix();
        glMatrixMode(GL_MODELVIEW);
    }
}

PlayerESPModule::PlayerESPModule(const BindType bindType, const int keyCode)
    : PlayerDataRender3dBaseModule(bindType, keyCode) {}

void PlayerESPModule::initializeFonts() {
    if (fontsInitialized) return;
    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig cfg;
    cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_Bitmap;
    cfg.FontDataOwnedByAtlas = false;

    for (float size = 2.0f; size <= 100.0f; size += 2.0f) {
        ImFont* f = io.Fonts->AddFontFromMemoryTTF(
            const_cast<void*>(static_cast<const void*>(Poppins_SemiBold_compressed_data.data())),
            static_cast<int>(Poppins_SemiBold_compressed_data.size()),
            size, &cfg, io.Fonts->GetGlyphRangesCyrillic());
        if (f) cachedFonts[size] = f;
    }
    io.Fonts->Build();
    ImGui_ImplOpenGL2_DestroyFontsTexture();
    ImGui_ImplOpenGL2_CreateFontsTexture();
    fontsInitialized = !cachedFonts.empty();
}

ImFont* PlayerESPModule::getOrCreateFont(float size) {
    if (!fontsInitialized) initializeFonts();
    ImFont* best = nullptr;
    float minDiff = FLT_MAX;
    for (const auto& [s, f] : cachedFonts) {
        if (f && f->ContainerAtlas && f->ContainerAtlas->TexID) {
            float d = std::abs(s - size);
            if (d < minDiff) { minDiff = d; best = f; if (d < 1.0f) return best; }
        }
    }
    if (best) return best;
    ImGuiIO& io = ImGui::GetIO();
    return io.Fonts->Fonts.empty() ? nullptr : io.Fonts->Fonts[0];
}

const char* PlayerESPModule::getItemTexturePath(int id) {

    switch (id) {
        case 298: return "textures/items/leather_helmet.png";
        case 299: return "textures/items/leather_chestplate.png";
        case 300: return "textures/items/leather_leggings.png";
        case 301: return "textures/items/leather_boots.png";
        case 302: return "textures/items/chainmail_helmet.png";
        case 303: return "textures/items/chainmail_chestplate.png";
        case 304: return "textures/items/chainmail_leggings.png";
        case 305: return "textures/items/chainmail_boots.png";
        case 306: return "textures/items/iron_helmet.png";
        case 307: return "textures/items/iron_chestplate.png";
        case 308: return "textures/items/iron_leggings.png";
        case 309: return "textures/items/iron_boots.png";
        case 310: return "textures/items/diamond_helmet.png";
        case 311: return "textures/items/diamond_chestplate.png";
        case 312: return "textures/items/diamond_leggings.png";
        case 313: return "textures/items/diamond_boots.png";
        case 314: return "textures/items/gold_helmet.png";
        case 315: return "textures/items/gold_chestplate.png";
        case 316: return "textures/items/gold_leggings.png";
        case 317: return "textures/items/gold_boots.png";

        case 268: return "textures/items/wood_sword.png";
        case 272: return "textures/items/stone_sword.png";
        case 267: return "textures/items/iron_sword.png";
        case 276: return "textures/items/diamond_sword.png";
        case 283: return "textures/items/gold_sword.png";

        case 271: return "textures/items/wood_axe.png";
        case 275: return "textures/items/stone_axe.png";
        case 258: return "textures/items/iron_axe.png";
        case 279: return "textures/items/diamond_axe.png";
        case 286: return "textures/items/gold_axe.png";

        case 261: return "textures/items/bow_standby.png";
        case 346: return "textures/items/fishing_rod_uncast.png";

        case 322: return "textures/items/apple_golden.png";
        default: return nullptr;
    }
}

const char* PlayerESPModule::getEnchantAbbrev(int id) {
    switch (id) {
        case 0:  return "P";   case 1:  return "FP";  case 2:  return "FF";
        case 3:  return "BP";  case 4:  return "PP";  case 7:  return "T";
        case 16: return "S";   case 17: return "Sm";  case 18: return "BA";
        case 19: return "KB";  case 20: return "FA";  case 21: return "Lo";
        case 32: return "E";   case 33: return "ST";  case 34: return "U";
        case 35: return "F";   case 48: return "Pw";  case 49: return "Pu";
        case 50: return "Fl";  case 51: return "Inf"; default: return "?";
    }
}

std::string PlayerESPModule::formatDuration(int ticks) {
    int s = ticks / 20;
    char buf[16];
    snprintf(buf, sizeof(buf), "%d:%02d", s / 60, s % 60);
    return buf;
}

void PlayerESPModule::collectPlayerData(JNIEnv* env) {
    for (auto& p : players) {
        for (auto& a : p.armorItems) { if (a) { env->DeleteGlobalRef(a); a = nullptr; } }
        if (p.heldItemRef) { env->DeleteGlobalRef(p.heldItemRef); p.heldItemRef = nullptr; }
        if (p.entityObject) { env->DeleteGlobalRef(p.entityObject); p.entityObject = nullptr; }
    }
    players.clear();
    if (!env) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    WorldClient world = mc.theWorld();
    EntityClientPlayerMP localPlayer = mc.thePlayer();
    if (world.isNull() || localPlayer.isNull()) return;

    Vec3D renderPos;
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        RenderManager rm = mc.getRenderManager();
        if (rm.isNull()) return;
        renderPos = rm.getRenderPos();
        env->DeleteLocalRef(rm.getObj());
    } else {
        RenderManager rm = RenderManager::getInstance(env);
        if (rm.isNull()) return;
        renderPos = rm.getRenderPos();
        env->DeleteLocalRef(rm.getObj());
    }

    float partialTicks = mc.timer().GetrenderPartialTicks();
    double lx = localPlayer.posX(), ly = localPlayer.posY(), lz = localPlayer.posZ();
    double llx = localPlayer.lastTickPosX(), lly = localPlayer.lastTickPosY(), llz = localPlayer.lastTickPosZ();
    localPlayerPos.x = static_cast<float>(llx + (lx - llx) * partialTicks - renderPos.x);
    localPlayerPos.y = static_cast<float>(lly + (ly - lly) * partialTicks - renderPos.y);
    localPlayerPos.z = static_cast<float>(llz + (lz - llz) * partialTicks - renderPos.z);

    ArrayList playerEntities = world.playerEntities();
    if (playerEntities.isNull()) return;

    static const int armorEnchIds[] = { 0, 1, 2, 3, 4, 7, 34 };
    static const int weaponEnchIds[] = { 16, 17, 18, 19, 20, 21, 32, 33, 34, 35, 48, 49, 50, 51 };

    const int count = playerEntities.size();
    for (int i = 0; i < count; i++) {

        if (env->PushLocalFrame(128) < 0) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            continue;
        }
        JavaObject entityObj = playerEntities.get(i);
        entityObj.setDeleteRef(false);
        auto target = entityObj.convertTo<EntityPlayer>();
        target.setDeleteRef(false);
        if (target.isNull() || localPlayer.entityId() == target.entityId() || target.isDead()) {
            env->PopLocalFrame(nullptr);
            continue;
        }

        { auto* ab = AntiBotModule::getInstancePtr();
          if (ab && ab->isBot(env, target.getObj())) {
              env->PopLocalFrame(nullptr); continue; } }

        PlayerData pd;
        double tx = target.posX(), ty = target.posY(), tz = target.posZ();
        double tlx = target.lastTickPosX(), tly = target.lastTickPosY(), tlz = target.lastTickPosZ();
        double ix = tlx + (tx - tlx) * partialTicks - renderPos.x;
        double iy = tly + (ty - tly) * partialTicks - renderPos.y;
        double iz = tlz + (tz - tlz) * partialTicks - renderPos.z;

        pd.position = { static_cast<float>(ix), static_cast<float>(iy + 2.2f), static_cast<float>(iz) };
        pd.feetPosition = { static_cast<float>(ix), static_cast<float>(iy), static_cast<float>(iz) };
        pd.distance = calculateDistance(localPlayerPos, pd.position);
        if (pd.distance > maxRenderDistance) {
            env->PopLocalFrame(nullptr);
            continue;
        }
        pd.health = target.getHealth();
        pd.maxHealth = 20.0f;
        pd.rotationYaw = target.rotationYaw();

        {
            EntityLivingBase elb(env, target.getObj());
            elb.setDeleteRef(false);
            float bodyNow = elb.renderYawOffset();
            float bodyPrev = elb.prevRenderYawOffset();

            float delta = bodyNow - bodyPrev;
            while (delta >= 180.0f) delta -= 360.0f;
            while (delta < -180.0f) delta += 360.0f;
            pd.bodyYaw = bodyPrev + delta * partialTicks;
            pd.headYaw = elb.rotationYawHead();

            float lsaNow = elb.limbSwingAmount();
            float lsaPrev = elb.prevLimbSwingAmount();
            pd.limbSwingAmount = lsaPrev + (lsaNow - lsaPrev) * partialTicks;
            pd.limbSwing = elb.limbSwing() - lsaNow * (1.0f - partialTicks);
        }

        if (showArmor) {

            static jmethodID getEquipSlotId = nullptr;
            static bool triedEquipSlot = false;
            if (!triedEquipSlot) {
                getEquipSlotId = Mappings::getInstance().getMethod("EntityPlayer#getEquipmentInSlot");
                triedEquipSlot = true;
            }

            bool gotAny = false;
            if (getEquipSlotId) {
                for (int eqSlot = 1; eqSlot <= 4; eqSlot++) {
                    jobject itemObj = env->CallObjectMethod(target.getObj(), getEquipSlotId, (jint)eqSlot);
                    if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
                    if (itemObj) {
                        int armorIdx = eqSlot - 1;
                        ItemStack item(env, itemObj);
                        item.setDeleteRef(false);
                        pd.armorItemIds[armorIdx] = item.getItemId();
                        pd.armorEnchanted[armorIdx] = item.isItemEnchanted();
                        pd.armorItems[armorIdx] = env->NewGlobalRef(itemObj);
                        gotAny = true;
                        if (pd.armorEnchanted[armorIdx]) {
                            for (int eid : armorEnchIds) {
                                int lvl = EnchantmentHelper::getEnchantmentLevel(env, eid, itemObj);
                                if (lvl > 0) pd.armorEnchantments[armorIdx].push_back({eid, lvl});
                            }
                        }
                    }
                }
            }

            if (!gotAny) {
                InventoryPlayer inv = target.inventoryPlayer();
                inv.setDeleteRef(false);
                if (!inv.isNull()) {
                    for (int slot = 0; slot < 4; slot++) {
                        if (pd.armorItems[slot]) continue;
                        ItemStack item = inv.getArmorItem(slot);
                        item.setDeleteRef(false);
                        if (!item.isNull()) {
                            pd.armorItemIds[slot] = item.getItemId();
                            pd.armorEnchanted[slot] = item.isItemEnchanted();
                            pd.armorItems[slot] = env->NewGlobalRef(item.getObj());
                            if (pd.armorEnchanted[slot]) {
                                for (int eid : armorEnchIds) {
                                    int lvl = EnchantmentHelper::getEnchantmentLevel(env, eid, item.getObj());
                                    if (lvl > 0) pd.armorEnchantments[slot].push_back({eid, lvl});
                                }
                            }
                        }
                    }
                }
            }
        }

        pd.entityId = target.entityId();
        if (showHeldItem) {
            ItemStack held = target.getCurrentEquippedItem();
            held.setDeleteRef(false);
            if (!held.isNull()) {
                pd.heldItemId = held.getItemId();
                pd.heldItemEnchanted = held.isItemEnchanted();
                pd.heldItemRef = env->NewGlobalRef(held.getObj());
                if (pd.heldItemEnchanted) {
                    for (int eid : weaponEnchIds) {
                        int lvl = EnchantmentHelper::getEnchantmentLevel(env, eid, held.getObj());
                        if (lvl > 0) pd.heldItemEnchantments.push_back({eid, lvl});
                    }
                }

                if (showGappleCount && pd.heldItemId == 322) {
                    int stack = held.getStackSize();
                    if (stack > 0) {
                        gappleCounts[pd.entityId] = stack;
                    }
                }
            }
        }

        auto it = gappleCounts.find(pd.entityId);
        if (it != gappleCounts.end()) pd.gappleCount = it->second;

        if (showPotionEffects) {
            static jmethodID gapId = nullptr, gpId = nullptr, gdId = nullptr, gaId = nullptr;
            auto& maps = Mappings::getInstance();
            if (!gapId) gapId = maps.getMethod("EntityLivingBase#getActivePotionEffects");
            if (!gpId)  gpId  = maps.getMethod("PotionEffect#getPotionID");
            if (!gdId)  gdId  = maps.getMethod("PotionEffect#getDuration");
            if (!gaId)  gaId  = maps.getMethod("PotionEffect#getAmplifier");

            if (gapId && gpId && gdId && gaId) {
                jobject coll = env->CallObjectMethod(target.getObj(), gapId);
                if (coll) {
                    static jmethodID iterId = nullptr, hasNId = nullptr, nextId = nullptr;
                    jclass cc = env->FindClass("java/util/Collection");
                    if (cc) {
                        if (!iterId) iterId = env->GetMethodID(cc, "iterator", "()Ljava/util/Iterator;");
                    }
                    jobject iter = (iterId) ? env->CallObjectMethod(coll, iterId) : nullptr;
                    if (iter) {
                        jclass ic = env->FindClass("java/util/Iterator");
                        if (ic) {
                            if (!hasNId) hasNId = env->GetMethodID(ic, "hasNext", "()Z");
                            if (!nextId) nextId = env->GetMethodID(ic, "next", "()Ljava/lang/Object;");
                        }
                        while (hasNId && nextId && env->CallBooleanMethod(iter, hasNId)) {
                            jobject pe = env->CallObjectMethod(iter, nextId);
                            if (pe) {
                                pd.potionEffects.push_back({
                                    env->CallIntMethod(pe, gpId),
                                    env->CallIntMethod(pe, gdId),
                                    env->CallIntMethod(pe, gaId)});
                            }
                        }
                    }
                }
            }
        }

        pd.entityObject = env->NewGlobalRef(target.getObj());

        pd.isValid = true;
        players.push_back(pd);
        env->PopLocalFrame(nullptr);
    }
}

void PlayerESPModule::renderSkeleton(ImDrawList* drawList, const PlayerData& player) {

    constexpr float HEAD_TOP = 1.875f;
    constexpr float NECK     = 1.406f;
    constexpr float SHOULDER_Y = 1.406f;
    constexpr float HAND_Y   = 0.703f;
    constexpr float HIP_Y    = 0.703f;
    constexpr float FOOT_Y   = 0.0f;
    constexpr float SHOULDER_OFFSET = 0.293f;
    constexpr float HIP_OFFSET      = 0.111f;

    float yawDeg = 180.0f - player.bodyYaw;
    float yawRad = yawDeg * 0.01745329f;
    float cosY = static_cast<float>(std::cos(yawRad));
    float sinY = static_cast<float>(std::sin(yawRad));

    const Vector3& f = player.feetPosition;

    const float lsa = std::min(player.limbSwingAmount, 1.0f);
    const float lsPhase = player.limbSwing * 0.6662f;
    const float cosPhase = std::cos(lsPhase);
    const float cosPhasePi = std::cos(lsPhase + 3.14159265f);

    const float armAngleL = cosPhase   * lsa;
    const float armAngleR = cosPhasePi * lsa;

    const float legAngleL = cosPhasePi * 1.4f * lsa;
    const float legAngleR = cosPhase   * 1.4f * lsa;

    const bool hasHeldItem = (player.heldItemId >= 0);
    const float itemTilt = 0.25f;

    auto limbEnd = [&](float offsetX, float limbLen, float pivotY, float swingAng) -> Vector3 {
        float c = std::cos(swingAng);
        float sn = std::sin(swingAng);

        float localY = pivotY - limbLen * c;
        float localZ = -limbLen * sn;

        Vector3 w;
        w.x = f.x + offsetX * cosY + localZ * sinY;
        w.y = f.y + localY;
        w.z = f.z + (-offsetX * sinY + localZ * cosY);
        return w;
    };

    Vector3 head     = { f.x, f.y + HEAD_TOP, f.z };
    Vector3 neck     = { f.x, f.y + NECK,     f.z };
    Vector3 shoulderL = { f.x + SHOULDER_OFFSET * cosY, f.y + SHOULDER_Y, f.z - SHOULDER_OFFSET * sinY };
    Vector3 shoulderR = { f.x - SHOULDER_OFFSET * cosY, f.y + SHOULDER_Y, f.z + SHOULDER_OFFSET * sinY };
    Vector3 hipCenter = { f.x, f.y + HIP_Y, f.z };
    Vector3 hipL     = { f.x + HIP_OFFSET * cosY, f.y + HIP_Y, f.z - HIP_OFFSET * sinY };
    Vector3 hipR     = { f.x - HIP_OFFSET * cosY, f.y + HIP_Y, f.z + HIP_OFFSET * sinY };

    const float armLen = SHOULDER_Y - HAND_Y;
    const float legLen = HIP_Y - FOOT_Y;

    float leftArmAngle  = armAngleL + (hasHeldItem ? itemTilt : 0.0f);
    float rightArmAngle = armAngleR;
    Vector3 handL = limbEnd(+SHOULDER_OFFSET, armLen, SHOULDER_Y, leftArmAngle);
    Vector3 handR = limbEnd(-SHOULDER_OFFSET, armLen, SHOULDER_Y, rightArmAngle);
    Vector3 footL = limbEnd(+HIP_OFFSET, legLen, HIP_Y, legAngleL);
    Vector3 footR = limbEnd(-HIP_OFFSET, legLen, HIP_Y, legAngleR);

    auto toScreen = [this](const Vector3& w, Vector2& s) { return worldToScreen(w, s); };

    Vector2 sHead, sNeck, sShL, sShR, sHaL, sHaR, sHip, sHiL, sHiR, sFoL, sFoR;
    if (!toScreen(head, sHead) || !toScreen(neck, sNeck) ||
        !toScreen(shoulderL, sShL) || !toScreen(shoulderR, sShR) ||
        !toScreen(handL, sHaL) || !toScreen(handR, sHaR) ||
        !toScreen(hipCenter, sHip) ||
        !toScreen(hipL, sHiL) || !toScreen(hipR, sHiR) ||
        !toScreen(footL, sFoL) || !toScreen(footR, sFoR)) {
        return;
    }

    const ImU32 col = ImGui::ColorConvertFloat4ToU32(skeletonColor.Value);
    const ImU32 outline = IM_COL32(0, 0, 0, 180);
    const float th = skeletonThickness;

    auto line = [&](const Vector2& a, const Vector2& b) {
        drawList->AddLine(ImVec2(a.x, a.y), ImVec2(b.x, b.y), outline, th + 1.5f);
        drawList->AddLine(ImVec2(a.x, a.y), ImVec2(b.x, b.y), col, th);
    };

    line(sHead, sNeck);
    line(sShL, sShR);
    line(sNeck, sHip);
    line(sShL, sHaL);
    line(sShR, sHaR);
    line(sHiL, sHiR);
    line(sHiL, sFoL);
    line(sHiR, sFoR);

    drawList->AddCircleFilled(ImVec2(sHead.x, sHead.y), th + 1.5f, outline);
    drawList->AddCircleFilled(ImVec2(sHead.x, sHead.y), th + 0.5f, col);
}

void PlayerESPModule::renderOutline(ImDrawList* drawList, const PlayerData& player) {

    if (outlineMode == 1) return;

    enum PartType { PT_HEAD = 0, PT_BODY = 1, PT_ARM_L = 2, PT_ARM_R = 3, PT_LEG_L = 4, PT_LEG_R = 5 };
    struct BodyPart { float cx, cy, cz, hx, hy, hz; int type; };
    static const BodyPart PARTS[] = {

        {  0.00f,  1.641f, 0.00f, 0.234f, 0.234f, 0.234f, PT_HEAD },

        {  0.00f,  1.055f, 0.00f, 0.234f, 0.352f, 0.117f, PT_BODY },

        {  0.352f, 1.055f, 0.00f, 0.117f, 0.352f, 0.117f, PT_ARM_L },
        { -0.352f, 1.055f, 0.00f, 0.117f, 0.352f, 0.117f, PT_ARM_R },

        {  0.117f, 0.352f, 0.00f, 0.117f, 0.352f, 0.117f, PT_LEG_L },
        { -0.117f, 0.352f, 0.00f, 0.117f, 0.352f, 0.117f, PT_LEG_R },
    };

    const BodyPart* parts = PARTS;
    const int partCount = 6;

    const bool hasHeldItem = (player.heldItemId >= 0);
    constexpr float SHOULDER_PIVOT_Y = 1.406f;
    constexpr float ITEM_TILT_RAD = 0.25f;

    constexpr float ARMOR_PAD = 0.03f;
    const bool hasHelmet  = (player.armorItemIds[3] >= 0);
    const bool hasChest   = (player.armorItemIds[2] >= 0);
    const bool hasLegs    = (player.armorItemIds[1] >= 0);
    const bool hasBoots   = (player.armorItemIds[0] >= 0);

    auto armorPadFor = [&](int type) -> float {
        switch (type) {
            case PT_HEAD: return hasHelmet ? ARMOR_PAD : 0.0f;
            case PT_BODY: return hasChest  ? ARMOR_PAD : 0.0f;
            case PT_ARM_L:
            case PT_ARM_R: return hasChest ? ARMOR_PAD : 0.0f;
            case PT_LEG_L:
            case PT_LEG_R: return (hasLegs || hasBoots) ? ARMOR_PAD : 0.0f;
            default: return 0.0f;
        }
    };

    float bodyYawDeg = 180.0f - player.bodyYaw;
    float bodyRad = bodyYawDeg * 0.01745329f;
    float bCos = static_cast<float>(std::cos(bodyRad));
    float bSin = static_cast<float>(std::sin(bodyRad));

    float headYawDeg = 180.0f - player.headYaw;
    float headRad = headYawDeg * 0.01745329f;
    float hCos = static_cast<float>(std::cos(headRad));
    float hSin = static_cast<float>(std::sin(headRad));

    const Vector3& f = player.feetPosition;

    constexpr float NECK_Y = 1.5f;

    auto rotateAndTranslateBody = [&](float lx, float ly, float lz, Vector3& out) {
        out.x = f.x + (lx * bCos + lz * bSin);
        out.y = f.y + ly;
        out.z = f.z + (-lx * bSin + lz * bCos);
    };
    auto rotateAndTranslateHead = [&](float lx, float ly, float lz, Vector3& out) {

        float py = ly - NECK_Y;
        out.x = f.x + (lx * hCos + lz * hSin);
        out.y = f.y + NECK_Y + py;
        out.z = f.z + (-lx * hSin + lz * hCos);
    };

    const ImU32 col = ImGui::ColorConvertFloat4ToU32(outlineColor.Value);
    const ImU32 outlineShadow = IM_COL32(0, 0, 0, 180);
    const float th = outlineThickness;

    auto rotateAroundX = [&](float& ly, float& lz, float angle, float pivotY) {
        float py = ly - pivotY;
        float c = std::cos(angle);
        float s = std::sin(angle);
        float ny = py * c - lz * s;
        float nz = py * s + lz * c;
        ly = pivotY + ny;
        lz = nz;
    };

    constexpr float HIP_PIVOT_Y = 0.703f;
    const float lsa = std::min(player.limbSwingAmount, 1.0f);
    const float lsPhase = player.limbSwing * 0.6662f;
    const float cosPhase = std::cos(lsPhase);
    const float cosPhasePi = std::cos(lsPhase + 3.14159265f);

    const float armAngleL = cosPhase   * lsa;
    const float armAngleR = cosPhasePi * lsa;

    const float legAngleL = cosPhasePi * 1.4f * lsa;
    const float legAngleR = cosPhase   * 1.4f * lsa;

    auto projectPart = [&](const BodyPart& p, Vector2 out[8]) -> bool {
        float pad = armorPadFor(p.type);
        float xs[2] = { p.cx - p.hx - pad, p.cx + p.hx + pad };
        float ys[2] = { p.cy - p.hy - pad, p.cy + p.hy + pad };
        float zs[2] = { p.cz - p.hz - pad, p.cz + p.hz + pad };

        float swingAngle = 0.0f;
        float swingPivot = 0.0f;
        bool isLimb = false;
        switch (p.type) {
            case PT_ARM_L: swingAngle = armAngleL; swingPivot = SHOULDER_PIVOT_Y; isLimb = true; break;
            case PT_ARM_R: swingAngle = armAngleR; swingPivot = SHOULDER_PIVOT_Y; isLimb = true; break;
            case PT_LEG_L: swingAngle = legAngleL; swingPivot = HIP_PIVOT_Y;     isLimb = true; break;
            case PT_LEG_R: swingAngle = legAngleR; swingPivot = HIP_PIVOT_Y;     isLimb = true; break;
            default: break;
        }

        const bool tiltThisArm = hasHeldItem && p.type == PT_ARM_L;

        for (int i = 0; i < 8; i++) {
            int ix = (i >> 0) & 1, iy = (i >> 1) & 1, iz = (i >> 2) & 1;
            float lx = xs[ix], ly = ys[iy], lz = zs[iz];

            if (isLimb && swingAngle != 0.0f) {
                rotateAroundX(ly, lz, swingAngle, swingPivot);
            }

            if (tiltThisArm) rotateAroundX(ly, lz, ITEM_TILT_RAD, SHOULDER_PIVOT_Y);
            Vector3 world;
            if (p.type == PT_HEAD) rotateAndTranslateHead(lx, ly, lz, world);
            else                    rotateAndTranslateBody(lx, ly, lz, world);
            if (!worldToScreen(world, out[i])) return false;
        }
        return true;
    };

    for (int pi = 0; pi < partCount; pi++) {
        const BodyPart& p = parts[pi];
        Vector2 screen[8];
        if (!projectPart(p, screen)) continue;

        static const int EDGES[12][2] = {
            {0,1},{2,3},{4,5},{6,7},
            {0,2},{1,3},{4,6},{5,7},
            {0,4},{1,5},{2,6},{3,7},
        };

        if (outlineGlow) {
            const float baseR = outlineColor.Value.x;
            const float baseG = outlineColor.Value.y;
            const float baseB = outlineColor.Value.z;
            const float baseA = outlineColor.Value.w;
            const int glowPasses = 5;
            for (int gp = glowPasses; gp >= 1; gp--) {
                float t = static_cast<float>(gp) / static_cast<float>(glowPasses);
                float passThickness = th + outlineGlowRadius * t;
                float passAlpha = baseA * (1.0f - t) * 0.35f;
                ImU32 glowCol = ImGui::ColorConvertFloat4ToU32(ImVec4(baseR, baseG, baseB, passAlpha));
                for (auto& e : EDGES) {
                    const Vector2& a = screen[e[0]];
                    const Vector2& b = screen[e[1]];
                    drawList->AddLine(ImVec2(a.x, a.y), ImVec2(b.x, b.y), glowCol, passThickness);
                }
            }
        }

        for (auto& e : EDGES) {
            const Vector2& a = screen[e[0]];
            const Vector2& b = screen[e[1]];
            if (!outlineGlow) {
                drawList->AddLine(ImVec2(a.x, a.y), ImVec2(b.x, b.y), outlineShadow, th + 1.5f);
            }
            drawList->AddLine(ImVec2(a.x, a.y), ImVec2(b.x, b.y), col, th);
        }
    }
}

void PlayerESPModule::renderArmorColumn(JNIEnv* env, ImDrawList* drawList,
                                         float centerX, float nametagTopY, float scaleFactor,
                                         float minWidth, const PlayerData& player) {
    const float s = scaleFactor * displayScale;
    const float enchFS = std::max(8.0f * s, 6.0f);
    const ImFont* ef = getOrCreateFont(enchFS);
    if (!ef) return;

    static jfieldID renderEngineId = nullptr;
    if (!renderEngineId) renderEngineId = Mappings::getInstance().getField("Minecraft#renderEngine");
    if (!renderEngineId) return;

    if (env->PushLocalFrame(32) < 0) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return;
    }

    Minecraft mc = Minecraft::getMinecraft(env);
    mc.setDeleteRef(false);
    if (mc.isNull()) { env->PopLocalFrame(nullptr); return; }
    jobject tmObj = env->GetObjectField(mc.getObj(), renderEngineId);
    if (!tmObj) { env->PopLocalFrame(nullptr); return; }
    TextureManager texMgr(env, tmObj);
    texMgr.setDeleteRef(false);

    struct Slot {
        int itemId;
        jobject ref;
        bool enchanted;
        int armorSlot;
        const std::vector<EnchantInfo>* enchants;
        int countOverride = 0;
    };
    std::vector<Slot> items;
    static const std::vector<EnchantInfo> emptyEnchants;

    for (int i = 3; i >= 0; i--) {
        if (player.armorItems[i])
            items.push_back({player.armorItemIds[i], player.armorItems[i],
                             player.armorEnchanted[i], i, &player.armorEnchantments[i], 0});
    }
    if (showHeldItem && player.heldItemRef)
        items.push_back({player.heldItemId, player.heldItemRef,
                         player.heldItemEnchanted, -1, &player.heldItemEnchantments, 0});
    if (showGappleCount && player.gappleCount > 0)
        items.push_back({322, nullptr, false, -2, &emptyEnchants, player.gappleCount});

    if (items.empty()) { env->PopLocalFrame(nullptr); return; }

    auto materialColor = [](int id) -> ImU32 {
        if (id >= 310 && id <= 313) return IM_COL32(100, 220, 255, 255);
        if (id >= 306 && id <= 309) return IM_COL32(200, 200, 200, 255);
        if (id >= 314 && id <= 317) return IM_COL32(255, 215, 50, 255);
        if (id >= 302 && id <= 305) return IM_COL32(160, 160, 170, 255);
        if (id >= 298 && id <= 301) return IM_COL32(160, 100, 60, 255);
        if (id == 276) return IM_COL32(100, 220, 255, 255);
        if (id == 267) return IM_COL32(200, 200, 200, 255);
        if (id == 283) return IM_COL32(255, 215, 50, 255);
        if (id == 272) return IM_COL32(160, 160, 160, 255);
        if (id == 268) return IM_COL32(180, 140, 80, 255);
        if (id == 261) return IM_COL32(150, 110, 60, 255);
        if (id == 346) return IM_COL32(140, 100, 50, 255);
        return IM_COL32(180, 180, 180, 255);
    };

    const float iconSz    = std::max(14.0f * s, 10.0f);
    const float slotGap   = 3.0f * s;
    const float padX      = 5.0f * s;
    const float padY      = 1.5f * s;
    const float textGapY  = 0.0f;
    const float rowGap    = 2.0f;
    const float indicatorH = std::max(1.0f, s);

    struct SlotInfo {
        std::string enchStr;
        ImVec2      enchSize;
        ImU32       matColor;
        float       slotW;
    };
    std::vector<SlotInfo> infos;
    infos.reserve(items.size());
    bool anyEnchant = false;

    for (auto& slot : items) {
        std::string enchStr;
        if (slot.armorSlot == -2) {
            enchStr = "x" + std::to_string(slot.countOverride);
        } else {

            for (size_t i = 0; i < slot.enchants->size(); i++) {
                enchStr += getEnchantAbbrev((*slot.enchants)[i].id);
                enchStr += std::to_string((*slot.enchants)[i].level);
            }
        }
        ImVec2 enchSize = enchStr.empty() ? ImVec2(0, 0) : ef->CalcTextSizeA(enchFS, FLT_MAX, 0, enchStr.c_str());
        float slotW = std::max(iconSz, enchSize.x);
        ImU32 matCol = (slot.armorSlot == -2) ? IM_COL32(255, 180, 50, 255) : materialColor(slot.itemId);
        if (!enchStr.empty()) anyEnchant = true;
        infos.push_back({std::move(enchStr), enchSize, matCol, slotW});
    }

    (void)minWidth;
    float totalW = padX;
    for (size_t i = 0; i < infos.size(); i++) {
        totalW += infos[i].slotW;
        if (i + 1 < infos.size()) totalW += slotGap;
    }
    totalW += padX;

    const float enchantRowH = anyEnchant ? (enchFS + textGapY) : 0.0f;
    const float rowH  = padY + enchantRowH + iconSz + indicatorH + padY;
    const float rowX0 = centerX - totalW * 0.5f;
    const float rowY1 = nametagTopY - rowGap;
    const float rowY0 = rowY1 - rowH;
    const float iconY = rowY0 + padY + enchantRowH;

    glDisable(GL_LIGHTING);
    glDisable(GL_DEPTH_TEST);
    glDisable(GL_CULL_FACE);
    glDisable(GL_TEXTURE_2D);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    auto glRect = [&](float x0, float y0, float x1, float y1, float r, float g, float b, float a) {
        glColor4f(r, g, b, a);
        glBegin(GL_QUADS);
        glVertex2f(x0, y0); glVertex2f(x1, y0);
        glVertex2f(x1, y1); glVertex2f(x0, y1);
        glEnd();
    };
    auto glRoundedRect = [](float x0, float y0, float x1, float y1, float radius,
                            float r, float g, float b, float a) {
        const float w = x1 - x0, h = y1 - y0;
        const float rr = std::min(radius, std::min(w, h) * 0.5f);
        glColor4f(r, g, b, a);
        if (rr <= 0.5f) {
            glBegin(GL_QUADS);
            glVertex2f(x0, y0); glVertex2f(x1, y0); glVertex2f(x1, y1); glVertex2f(x0, y1);
            glEnd();
            return;
        }
        constexpr int segs = 5;
        constexpr float pi = 3.14159265f;

        const float ccx[4] = { x1 - rr, x0 + rr, x0 + rr, x1 - rr };
        const float ccy[4] = { y0 + rr, y0 + rr, y1 - rr, y1 - rr };
        const float ang0[4] = { 0.0f, 0.5f * pi, pi, 1.5f * pi };
        glBegin(GL_TRIANGLE_FAN);
        glVertex2f((x0 + x1) * 0.5f, (y0 + y1) * 0.5f);
        for (int c = 0; c < 4; c++) {
            for (int i = 0; i <= segs; i++) {
                const float a2 = ang0[c] + (0.5f * pi) * (float(i) / segs);
                glVertex2f(ccx[c] + std::cos(a2) * rr,
                           ccy[c] - std::sin(a2) * rr);
            }
        }

        glVertex2f(ccx[0] + rr, ccy[0]);
        glEnd();
    };
    auto unpackU32 = [](ImU32 c, float out[4]) {
        out[0] = ((c >> IM_COL32_R_SHIFT) & 0xFF) / 255.0f;
        out[1] = ((c >> IM_COL32_G_SHIFT) & 0xFF) / 255.0f;
        out[2] = ((c >> IM_COL32_B_SHIFT) & 0xFF) / 255.0f;
        out[3] = ((c >> IM_COL32_A_SHIFT) & 0xFF) / 255.0f;
    };

    float curX = rowX0 + padX;
    for (size_t i = 0; i < items.size(); i++) {
        float iconX = curX + (infos[i].slotW - iconSz) * 0.5f;
        float c[4]; unpackU32(infos[i].matColor, c);

        glRect(iconX, iconY + iconSz, iconX + iconSz, iconY + iconSz + indicatorH,
               c[0], c[1], c[2], c[3] * 0.55f);
        curX += infos[i].slotW + slotGap;
    }

    glEnable(GL_TEXTURE_2D);
    glEnable(GL_ALPHA_TEST);
    glAlphaFunc(GL_GREATER, 0.001f);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);

    curX = rowX0 + padX;
    for (size_t i = 0; i < items.size(); i++) {
        float iconX = curX + (infos[i].slotW - iconSz) * 0.5f;
        const char* texPath = getItemTexturePath(items[i].itemId);
        if (texPath) {
            ResourceLocation rl(env, texPath);
            rl.setDeleteRef(false);
            if (!rl.isNull()) {
                texMgr.bindTexture(rl);
                glColor4f(1, 1, 1, 1);
                glBegin(GL_QUADS);
                glTexCoord2f(0, 0); glVertex2f(iconX,         iconY);
                glTexCoord2f(1, 0); glVertex2f(iconX + iconSz, iconY);
                glTexCoord2f(1, 1); glVertex2f(iconX + iconSz, iconY + iconSz);
                glTexCoord2f(0, 1); glVertex2f(iconX,         iconY + iconSz);
                glEnd();

                if (items[i].enchanted) {
                    glBlendFunc(GL_SRC_ALPHA, GL_ONE);
                    float t = static_cast<float>(GetTickCount() % 2000) / 2000.0f;
                    float pulse = 0.3f + 0.15f * std::sin(t * 6.2831853f);
                    glColor4f(0.5f, 0.2f, 1.0f, pulse);
                    glBegin(GL_QUADS);
                    glTexCoord2f(0, 0); glVertex2f(iconX,         iconY);
                    glTexCoord2f(1, 0); glVertex2f(iconX + iconSz, iconY);
                    glTexCoord2f(1, 1); glVertex2f(iconX + iconSz, iconY + iconSz);
                    glTexCoord2f(0, 1); glVertex2f(iconX,         iconY + iconSz);
                    glEnd();
                    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
                }
            }
        }
        curX += infos[i].slotW + slotGap;
    }

    glDisable(GL_ALPHA_TEST);
    glDisable(GL_TEXTURE_2D);

    if (anyEnchant) {
        curX = rowX0 + padX;
        for (size_t i = 0; i < items.size(); i++) {
            if (!infos[i].enchStr.empty()) {
                float textX = curX + (infos[i].slotW - infos[i].enchSize.x) * 0.5f;
                float textY = iconY - textGapY - enchFS;
                draw->text(drawList, ef, enchFS, ImVec2(textX, textY),
                           IM_COL32(85, 255, 255, 255), infos[i].enchStr.c_str());
            }
            curX += infos[i].slotW + slotGap;
        }
    }

    env->PopLocalFrame(nullptr);
}

void PlayerESPModule::renderPotionColumn(JNIEnv* env, ImDrawList* drawList, float centerX, float armorTopY,
                                          float scaleFactor, float minWidth, const PlayerData& player) {
    if (!showPotionEffects || player.potionEffects.empty()) return;
    const float s = scaleFactor * displayScale;
    const float fs = std::max(8.0f * s, 6.0f);
    const ImFont* f = getOrCreateFont(fs);
    if (!f) return;

    auto getIconIdx = [](int id) -> int {
        switch (id) {
            case 1:  return 0;
            case 2:  return 1;
            case 3:  return 2;
            case 4:  return 3;
            case 5:  return 4;
            case 8:  return 10;
            case 9:  return 11;
            case 10: return 7;
            case 11: return 14;
            case 12: return 15;
            case 13: return 16;
            case 14: return 8;
            case 15: return 13;
            case 16: return 12;
            case 17: return 9;
            case 18: return 5;
            case 19: return 6;
            case 20: return 17;
            case 21: return 23;
            case 22: return 18;
            default: return -1;
        }
    };

    ImTextureID iconTexId = nullptr;
    if (env) {
        static jfieldID renderEngineId = nullptr;
        if (!renderEngineId) renderEngineId = Mappings::getInstance().getField("Minecraft#renderEngine");
        if (renderEngineId) {
            Minecraft mc = Minecraft::getMinecraft(env);
            mc.setDeleteRef(false);
            if (!mc.isNull()) {
                jobject tmObj = env->GetObjectField(mc.getObj(), renderEngineId);
                if (tmObj) {
                    TextureManager texMgr(env, tmObj);
                    texMgr.setDeleteRef(false);
                    ResourceLocation rl(env, "textures/gui/container/inventory.png");
                    rl.setDeleteRef(false);
                    if (!rl.isNull()) {
                        texMgr.bindTexture(rl);
                        GLint curTex = 0;
                        glGetIntegerv(GL_TEXTURE_BINDING_2D, &curTex);
                        iconTexId = reinterpret_cast<ImTextureID>(static_cast<intptr_t>(curTex));
                    }
                    env->DeleteLocalRef(tmObj);
                }
            }
        }
    }

    const float iconSz    = std::max(fs * 1.35f, 12.0f);
    const float padX      = 3.0f * s;
    const float padY      = 2.0f * s;
    const float iconGap   = 3.0f * s;
    const float pillGap   = 3.0f * s;
    const float pillH     = iconSz + padY * 2.0f;
    const float rowGap    = 2.0f;

    struct PillData {
        std::string time;
        ImVec2 timeSize;
        int iconIdx;
        float pillW;
    };
    std::vector<PillData> pills;
    pills.reserve(player.potionEffects.size());
    float totalW = padX;

    for (size_t i = 0; i < player.potionEffects.size(); i++) {
        const auto& eff = player.potionEffects[i];
        std::string time = formatDuration(eff.duration);
        ImVec2 timeSize  = f->CalcTextSizeA(fs, FLT_MAX, 0, time.c_str());
        int iconIdx = getIconIdx(eff.potionId);
        float pillW = iconSz + iconGap + timeSize.x + padX;
        if (i > 0) totalW += pillGap;
        totalW += pillW;
        pills.push_back({std::move(time), timeSize, iconIdx, pillW});
    }
    totalW += padX;
    (void)minWidth;

    const float rowY1 = armorTopY - rowGap;
    const float rowY0 = rowY1 - pillH;
    const float rowX0 = centerX - totalW * 0.5f;

    draw->rect_filled(drawList, ImVec2(rowX0, rowY0), ImVec2(rowX0 + totalW, rowY1),
                      IM_COL32(0, 0, 0, 178), 3.0f, draw_flags_round_corners_all);

    float curX = rowX0 + padX;
    for (const auto& pill : pills) {
        const float iconX = curX;
        const float iconY = rowY0 + (pillH - iconSz) * 0.5f;

        if (iconTexId && pill.iconIdx >= 0) {
            const int col = pill.iconIdx % 8;
            const int row = pill.iconIdx / 8;
            const float u0 = (col * 18.0f) / 256.0f;
            const float v0 = (198.0f + row * 18.0f) / 256.0f;
            const float u1 = u0 + 18.0f / 256.0f;
            const float v1 = v0 + 18.0f / 256.0f;
            drawList->AddImage(iconTexId,
                               ImVec2(iconX, iconY),
                               ImVec2(iconX + iconSz, iconY + iconSz),
                               ImVec2(u0, v0), ImVec2(u1, v1));
        }

        const float textX = iconX + iconSz + iconGap;
        const float textY = rowY0 + (pillH - fs) * 0.5f;
        draw->text(drawList, f, fs, ImVec2(textX, textY),
                   IM_COL32(230, 230, 230, 255), pill.time.c_str());

        curX += pill.pillW + pillGap;
    }
}

void PlayerESPModule::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    showArmor         = features.size() > 0 && features[0];
    showPotionEffects = features.size() > 1 && features[1];
    showHeldItem      = features.size() > 2 && features[2];
    showSkeleton      = features.size() > 3 && features[3];
    showOutline       = features.size() > 4 && features[4];
    showGappleCount   = features.size() > 5 && features[5];
    unifyWithNametag  = features.size() > 6 && features[6];

    auto* gs = ProviderHandler::getInstance().getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (!gs || !gs->inGameHasFocus() || gs->isChestOpen() || gs->isOptionsOpen() || gs->isInventoryOpen()) return;

    updateMatrices(env);
    collectPlayerData(env);
    if (projectionMatrix.size() != 16 || modelViewMatrix.size() != 16) return;

    ImDrawList* drawList = GetBackgroundDrawList();
    if (!drawList) return;

    const ImGuiIO& io = GetIO();
    const float sw = io.DisplaySize.x, sh = io.DisplaySize.y;

    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadIdentity();
    glOrtho(0, sw, sh, 0, -1, 1);
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadIdentity();
    glDisable(GL_DEPTH_TEST);

    for (const auto& p : players) {
        if (!p.isValid) continue;

        Vector2 headScreen{}, feetScreen{}, nametagScreen{};
        Vector3 headPos = p.position; headPos.y += 0.3f;

        if (!worldToScreen(p.position, nametagScreen)) continue;
        if (!std::isfinite(nametagScreen.x) || !std::isfinite(nametagScreen.y)) continue;

        const bool haveHead = worldToScreen(headPos, headScreen)
                           && std::isfinite(headScreen.x) && std::isfinite(headScreen.y);
        const bool haveFeet = worldToScreen(p.feetPosition, feetScreen)
                           && std::isfinite(feetScreen.x) && std::isfinite(feetScreen.y);

        float boxH, centerX;
        if (haveHead && haveFeet) {

            boxH = std::abs(feetScreen.y - headScreen.y);
            centerX = (headScreen.x + feetScreen.x) * 0.5f;
        } else {

            const float d = std::max(p.distance, 0.5f);
            boxH = std::clamp(1.8f / d * sh * 0.7f, 50.0f, sh * 0.9f);
            centerX = nametagScreen.x;
        }

        float scaleFactor = std::clamp(boxH / (0.33038348082f * sh), 0.0f, 1.0f);
        if (scaleFactor < 0.2f) scaleFactor = 0.2f;

        auto* ntMod = ModuleHandler::getInstance().getModule<ModuleType::NAMETAG>();
        const bool nametagActive = (ntMod && ntMod->isEnabled());

        const float s = scaleFactor * displayScale;
        const float enchFS = std::max(8.0f * s, 6.0f);
        const float iconSz  = std::max(14.0f * s, 10.0f);
        const float slotGap = 3.0f * s;
        const float aPadX   = 5.0f * s;

        float approxArmorW = 0.0f;
        if (showArmor) {
            const ImFont* ef = getOrCreateFont(enchFS);
            float tw = aPadX;
            bool first = true;
            for (int i = 3; i >= 0; i--) {
                if (p.armorItemIds[i] == -1) continue;
                float armorSlotW = iconSz;
                if (ef && p.armorEnchanted[i] && !p.armorEnchantments[i].empty()) {
                    std::string es;
                    for (size_t j = 0; j < p.armorEnchantments[i].size(); j++) {
                        if (j > 0) es += " ";
                        es += getEnchantAbbrev(p.armorEnchantments[i][j].id);
                        es += std::to_string(p.armorEnchantments[i][j].level);
                    }
                    armorSlotW = std::max(armorSlotW, ef->CalcTextSizeA(enchFS, FLT_MAX, 0, es.c_str()).x);
                }
                if (!first) tw += slotGap; tw += armorSlotW; first = false;
            }
            if (showHeldItem && p.heldItemId != -1 && p.heldItemRef) {
                if (!first) tw += slotGap;
                tw += iconSz; first = false;
            }
            if (showGappleCount && p.gappleCount > 0) {
                if (!first) tw += slotGap;
                tw += iconSz;
            }
            tw += aPadX;
            approxArmorW = tw;
        }

        float approxPotionW = 0.0f;
        if (showPotionEffects && !p.potionEffects.empty()) {
            const ImFont* pf = getOrCreateFont(enchFS);
            float tw = 4.0f * s;
            const float indW = 3.0f * s, pPadX = 4.0f * s, tGap = 4.0f * s, pGap = 2.0f * s;
            for (size_t i = 0; i < p.potionEffects.size(); i++) {
                float pillW = indW + pPadX;
                if (pf) {

                    pillW += pf->CalcTextSizeA(enchFS, FLT_MAX, 0, "Resist").x + tGap
                           + pf->CalcTextSizeA(enchFS, FLT_MAX, 0, "0:00").x + pPadX;
                }
                if (i > 0) tw += pGap;
                tw += pillW;
            }
            tw += 4.0f * s;
            approxPotionW = tw;
        }

        float blockW = std::max(approxArmorW, approxPotionW);

        bool anyArmorEnchant = false;
        for (int i = 0; i < 4; i++) if (p.armorEnchanted[i]) { anyArmorEnchant = true; break; }
        if (showHeldItem && p.heldItemEnchanted) anyArmorEnchant = true;
        const float textGapY   = 0.0f;
        const float armorPadY  = 1.5f * s;
        const float indicatorH = std::max(1.0f, s);
        const float armorEnchH = anyArmorEnchant ? (enchFS + textGapY) : 0.0f;
        const float armorRowH  = armorPadY + armorEnchH + iconSz + indicatorH + armorPadY;
        const float armorRowGap = 2.0f;
        const float armorTopY  = nametagScreen.y - armorRowGap - armorRowH;

        if (unifyWithNametag && nametagActive && blockW > 0.0f)
            sharedBlockW[p.entityId] = blockW;
        else
            sharedBlockW.erase(p.entityId);

        if (showOutline) renderOutline(drawList, p);
        if (showSkeleton) renderSkeleton(drawList, p);

        if (showArmor) {
            renderArmorColumn(env, drawList, centerX, nametagScreen.y, scaleFactor, blockW, p);
        }

        if (showPotionEffects && !p.potionEffects.empty()) {
            renderPotionColumn(env, drawList, centerX, armorTopY, scaleFactor, blockW, p);
        }
    }

    glEnable(GL_DEPTH_TEST);
    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();
}

bool PlayerESPModule::worldToScreen(const Vector3& worldPos, Vector2& screenPos) {
    return Render3dBaseModule::worldToScreen(worldPos, screenPos, projectionMatrix, modelViewMatrix);
}

bool PlayerESPModule::updateMatrices(JNIEnv* env) {
    projectionMatrix = ActiveRenderInfo::GetProjectionMatrix(env);
    modelViewMatrix = ActiveRenderInfo::GetModelViewMatrix(env);
    return true;
}

void PlayerESPModule::renderOutlineOverlay(JNIEnv* env) {
    if (!isEnabled() || !showOutline || outlineMode != 1) return;
    if (!env) return;
    if (players.empty()) return;

    auto* gs = ProviderHandler::getInstance()
        .getTypedProvider<GameStateProvider, ProviderType::GAME_STATE>();
    if (gs && (!gs->inGameHasFocus() || gs->isChestOpen()
               || gs->isOptionsOpen() || gs->isInventoryOpen())) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;
    RenderManager renderManager = mc.getRenderManager();
    if (renderManager.isNull()) return;

    float partialTicks = mc.timer().GetrenderPartialTicks();

    GameSettings gameSettings = mc.gameSettings();
    bool origShadows = true;
    bool gsValid = !gameSettings.isNull();
    if (gsValid) {
        gameSettings.setDeleteRef(false);
        origShadows = gameSettings.entityShadows();
        gameSettings.setEntityShadows(false);
    }

    PlayerESPModule::isRenderingOutline = true;

    ActiveRenderInfo2 activeRenderInfo = ActiveRenderInfo2::getInstance(env);
    std::array<double, 16> modelView{};
    std::array<double, 16> projection{};
    activeRenderInfo.getModelView(modelView);
    activeRenderInfo.getProjection(projection);

    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadMatrixd(projection.data());
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadMatrixd(modelView.data());

    glPushAttrib(GL_ALL_ATTRIB_BITS);

    const float r = outlineColor.Value.x;
    const float g = outlineColor.Value.y;
    const float b = outlineColor.Value.z;
    const float a = outlineColor.Value.w;

    glColorMask(GL_FALSE, GL_FALSE, GL_FALSE, GL_FALSE);
    glDepthMask(GL_TRUE);
    GlStateManager::depthMask(env, true);
    glEnable(GL_DEPTH_TEST);
    GlStateManager::enableDepth(env);
    glDepthFunc(GL_LEQUAL);
    glDisable(GL_BLEND);
    GlStateManager::disableBlend(env);
    glDisable(0x0B60);
    glDisable(GL_LIGHTING);

    for (const auto& player : players) {
        if (!player.isValid || !player.entityObject) continue;
        EntityPlayer entity(env, player.entityObject);
        entity.setDeleteRef(false);
        if (entity.isNull()) continue;

        GlStateManager::depthMask(env, true);
        glDepthMask(GL_TRUE);
        glDepthFunc(GL_LEQUAL);
        renderManager.renderEntitySimple(entity, partialTicks);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }

    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    glDepthMask(GL_FALSE);
    GlStateManager::depthMask(env, false);
    glEnable(GL_BLEND);
    glDepthRange(0.5, 1.0);

    const float baseScale = 1.0f + outlineThickness * 0.01f;

    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_REPLACE);
    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB, GL_CONSTANT_TEX);
    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_MODULATE);
    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA, GL_TEXTURE);
    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_ALPHA, GL_CONSTANT_TEX);

    auto renderPlayersAtScale = [&](float sc, float ra, float ga, float ba, float aa) {
        const float ec[4] = { ra, ga, ba, aa };
        for (const auto& player : players) {
            if (!player.isValid || !player.entityObject) continue;
            EntityPlayer entity(env, player.entityObject);
            entity.setDeleteRef(false);
            if (entity.isNull()) continue;

            glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
            glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB,   GL_REPLACE);
            glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB,   GL_CONSTANT_TEX);
            glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_MODULATE);
            glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA, GL_TEXTURE);
            glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_ALPHA, GL_CONSTANT_TEX);
            glTexEnvfv(GL_TEXTURE_ENV, GL_TEXTURE_ENV_COLOR, ec);
            glColor4f(ra, ga, ba, aa);
            glDepthFunc(GL_LEQUAL);
            glEnable(GL_TEXTURE_2D);

            const double rx = static_cast<double>(player.feetPosition.x);
            const double ry = static_cast<double>(player.feetPosition.y) + 0.9;
            const double rz = static_cast<double>(player.feetPosition.z);
            glPushMatrix();
            glTranslated(rx, ry, rz);
            glScalef(sc, sc, sc);
            glTranslated(-rx, -ry, -rz);
            renderManager.renderEntitySimple(entity, partialTicks);
            if (env->ExceptionCheck()) env->ExceptionClear();
            glPopMatrix();
        }
    };

    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    renderPlayersAtScale(baseScale, r, g, b, a);

    if (outlineGlow) {
        initFBOFuncs();
        if (s_fboFuncOk) {
            GLint vp[4] = {};
            glGetIntegerv(GL_VIEWPORT, vp);
            const int vpW = vp[2], vpH = vp[3];
            const int hw  = std::max(1, vpW / 2);
            const int hh  = std::max(1, vpH / 2);

            if (s_pingFBO.ensure(hw, hh, true) && s_pongFBO.ensure(hw, hh, false)) {
                GLint savedFB = 0;
                glGetIntegerv(GL_FRAMEBUFFER_BINDING, &savedFB);

                s_glBindFB(GL_FRAMEBUFFER, s_pingFBO.fbo);
                glViewport(0, 0, hw, hh);
                glClearColor(0.f, 0.f, 0.f, 0.f);
                glClearDepth(1.0);
                glDepthMask(GL_TRUE);
                glStencilMask(0xFF);
                glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

                glEnable(GL_DEPTH_TEST);
                glDepthFunc(GL_LEQUAL);
                glDepthMask(GL_TRUE);
                glDisable(GL_BLEND);
                glDisable(GL_LIGHTING);
                glDisable(0x0B60);
                glDisable(GL_CULL_FACE);
                glEnable(GL_ALPHA_TEST);
                glAlphaFunc(GL_GREATER, 0.1f);

                const float ec[4] = { r, g, b, 1.0f };

                for (const auto& player : players) {
                    if (!player.isValid || !player.entityObject) continue;
                    EntityPlayer entity(env, player.entityObject);
                    entity.setDeleteRef(false);
                    if (entity.isNull()) continue;

                    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
                    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB,   GL_REPLACE);
                    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB,   GL_CONSTANT_TEX);
                    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_REPLACE);
                    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA, GL_TEXTURE);
                    glTexEnvfv(GL_TEXTURE_ENV, GL_TEXTURE_ENV_COLOR, ec);
                    glColor4f(r, g, b, 1.0f);
                    glDepthFunc(GL_LEQUAL);
                    glEnable(GL_ALPHA_TEST);
                    glAlphaFunc(GL_GREATER, 0.1f);

                    renderManager.renderEntitySimple(entity, partialTicks);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                }

                glDisable(GL_ALPHA_TEST);

                const float baseD = 0.5f + outlineGlowRadius * 0.30f;

                s_glBindFB(GL_FRAMEBUFFER, s_pongFBO.fbo);
                glViewport(0, 0, hw, hh);
                kawasePass(s_pingFBO.tex, hw, hh, baseD);

                s_glBindFB(GL_FRAMEBUFFER, s_pingFBO.fbo);
                glViewport(0, 0, hw, hh);
                kawasePass(s_pongFBO.tex, hw, hh, baseD * 2.0f);

                s_glBindFB(GL_FRAMEBUFFER, s_pongFBO.fbo);
                glViewport(0, 0, hw, hh);
                kawasePass(s_pingFBO.tex, hw, hh, baseD * 4.0f);

                s_glBindFB(GL_FRAMEBUFFER, static_cast<GLuint>(savedFB));
                glViewport(vp[0], vp[1], vpW, vpH);

                glEnable(GL_DEPTH_TEST);
                glDepthFunc(GL_LEQUAL);
                glDepthMask(GL_FALSE);
                glDepthRange(1.0, 1.0);

                glEnable(GL_BLEND);
                glBlendFunc(GL_SRC_ALPHA, GL_ONE);
                glEnable(GL_TEXTURE_2D);

                glBindTexture(GL_TEXTURE_2D, s_pongFBO.tex);
                glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
                glColor4f(1.f, 1.f, 1.f, a);

                glMatrixMode(GL_PROJECTION); glPushMatrix(); glLoadIdentity();
                glOrtho(0.0, 1.0, 0.0, 1.0, -1.0, 1.0);
                glMatrixMode(GL_MODELVIEW);  glPushMatrix(); glLoadIdentity();

                for (int p = 0; p < 3; p++) {
                    glBegin(GL_QUADS);
                        glTexCoord2f(0.f, 0.f); glVertex2f(0.f, 0.f);
                        glTexCoord2f(1.f, 0.f); glVertex2f(1.f, 0.f);
                        glTexCoord2f(1.f, 1.f); glVertex2f(1.f, 1.f);
                        glTexCoord2f(0.f, 1.f); glVertex2f(0.f, 1.f);
                    glEnd();
                }

                glBindTexture(GL_TEXTURE_2D, 0);
                glMatrixMode(GL_MODELVIEW);  glPopMatrix();
                glMatrixMode(GL_PROJECTION); glPopMatrix();
                glMatrixMode(GL_MODELVIEW);

                glDepthRange(0.0, 1.0);
            }
        }
    }

    glDepthRange(0.0, 1.0);

    glClear(GL_DEPTH_BUFFER_BIT);

    if (gsValid) {
        gameSettings.setEntityShadows(origShadows);
    }

    PlayerESPModule::isRenderingOutline = false;

    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
    glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    glPopAttrib();

    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();
    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);

    GlStateManager::enableDepth(env);
    GlStateManager::enableTexture2D(env);
    GlStateManager::enableLighting(env);
    GlStateManager::depthMask(env, true);
    GlStateManager::disableBlend(env);
    GlStateManager::color(env, 1.0f, 1.0f, 1.0f, 1.0f);
}

REGISTER_MODULE(PlayerESPModule, ModuleType::PLAYER_ESP)
