#include "module/impl/visual/ChamsModule.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/entity/player/EntityPlayer.h"
#include "wrapper/minecraft/entity/render/RenderManager.h"
#include "wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h"
#include "wrapper/java/util/ArrayList.h"
#include "setting/SettingMacros.h"
#include "handler/MappingHandler.h"
#include "handler/ModuleHandler.h"
#include "module/impl/combat/AntiBotModule.h"
#include "util/RenderUtils.h"

#include <windows.h>
#include <gl/GL.h>
#include <iostream>

#ifndef GL_ALL_ATTRIB_BITS
#define GL_ALL_ATTRIB_BITS 0x000FFFFF
#endif
#ifndef GL_TEXTURE_2D
#define GL_TEXTURE_2D 0x0DE1
#endif
#ifndef GL_LIGHTING
#define GL_LIGHTING 0x0B50
#endif
#ifndef GL_TEXTURE_ENV
#define GL_TEXTURE_ENV 0x2300
#endif
#ifndef GL_TEXTURE_ENV_MODE
#define GL_TEXTURE_ENV_MODE 0x2200
#endif
#ifndef GL_TEXTURE_ENV_COLOR
#define GL_TEXTURE_ENV_COLOR 0x2201
#endif
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
#ifndef GL_SOURCE1_RGB
#define GL_SOURCE1_RGB 0x8581
#endif
#ifndef GL_SOURCE0_ALPHA
#define GL_SOURCE0_ALPHA 0x8588
#endif
#ifndef GL_CONSTANT_TEX
#define GL_CONSTANT_TEX 0x8576
#endif
#ifndef GL_MODULATE
#define GL_MODULATE 0x2100
#endif
#ifndef GL_REPLACE
#define GL_REPLACE 0x1E01
#endif
#ifndef GL_TEXTURE
#define GL_TEXTURE 0x1702
#endif
#ifndef GL_TEXTURE0
#define GL_TEXTURE0 0x84C0
#endif
#ifndef GL_TEXTURE1
#define GL_TEXTURE1 0x84C1
#endif

typedef void (APIENTRY* PFNGLACTIVETEXTUREPROC)(GLenum texture);
static PFNGLACTIVETEXTUREPROC glActiveTexture = nullptr;

static void resolveGlActiveTexture() {
    if (!glActiveTexture) {
        glActiveTexture = (PFNGLACTIVETEXTUREPROC)wglGetProcAddress("glActiveTexture");
    }
}

namespace gsm {
    static jclass    cls = nullptr;
    static jmethodID enableDepth     = nullptr;
    static jmethodID disableDepth    = nullptr;
    static jmethodID depthMask       = nullptr;
    static jmethodID depthFunc       = nullptr;
    static jmethodID enableTexture2D = nullptr;
    static jmethodID disableTexture2D= nullptr;
    static jmethodID enableLighting  = nullptr;
    static jmethodID disableLighting = nullptr;
    static jmethodID enableBlend     = nullptr;
    static jmethodID disableBlend    = nullptr;
    static jmethodID enableAlpha     = nullptr;
    static jmethodID enableCull      = nullptr;
    static jmethodID disableFog      = nullptr;
    static jmethodID color           = nullptr;
    static jmethodID tryBlendFuncSeparate = nullptr;
    static jmethodID setActiveTexture = nullptr;
    static bool resolved  = false;
    static bool available = false;

    jclass findGlobalClass(JNIEnv* env, const char* name) {
        jclass local = env->FindClass(name);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
        if (!local) return nullptr;
        auto global = static_cast<jclass>(env->NewGlobalRef(local));
        env->DeleteLocalRef(local);
        return global;
    }

    void resolve(JNIEnv* env) {
        if (resolved) return;
        resolved = true;

        auto& maps = Mappings::getInstance();
        cls = maps.getClass("GlStateManager");
        if (!cls) return;

        auto resolveStatic = [&](const char* mappingKey, const char* fallbackName,
                                 const char* sig) -> jmethodID {
            if (jmethodID m = maps.getMethod(mappingKey)) return m;
            jmethodID m = env->GetStaticMethodID(cls, fallbackName, sig);
            if (env->ExceptionCheck()) env->ExceptionClear();
            return m;
        };

        enableDepth          = resolveStatic("GlStateManager#enableDepth",          "enableDepth",          "()V");
        disableDepth         = resolveStatic("GlStateManager#disableDepth",         "disableDepth",         "()V");
        depthMask            = resolveStatic("GlStateManager#depthMask",            "depthMask",            "(Z)V");
        depthFunc            = resolveStatic("GlStateManager#depthFunc",            "depthFunc",            "(I)V");
        enableTexture2D      = resolveStatic("GlStateManager#enableTexture2D",      "enableTexture2D",      "()V");
        disableTexture2D     = resolveStatic("GlStateManager#disableTexture2D",     "disableTexture2D",     "()V");
        enableLighting       = resolveStatic("GlStateManager#enableLighting",       "enableLighting",       "()V");
        disableLighting      = resolveStatic("GlStateManager#disableLighting",      "disableLighting",      "()V");
        enableBlend          = resolveStatic("GlStateManager#enableBlend",          "enableBlend",          "()V");
        disableBlend         = resolveStatic("GlStateManager#disableBlend",         "disableBlend",         "()V");
        enableAlpha          = resolveStatic("GlStateManager#enableAlpha",          "enableAlpha",          "()V");
        enableCull           = resolveStatic("GlStateManager#enableCull",           "enableCull",           "()V");
        disableFog           = resolveStatic("GlStateManager#disableFog",           "disableFog",           "()V");

        color                = resolveStatic("GlStateManager#color_F_F_F_F",        "color",                "(FFFF)V");
        tryBlendFuncSeparate = resolveStatic("GlStateManager#tryBlendFuncSeparate", "tryBlendFuncSeparate", "(IIII)V");
        setActiveTexture     = resolveStatic("GlStateManager#setActiveTexture",     "setActiveTexture",     "(I)V");
        if (env->ExceptionCheck()) env->ExceptionClear();

        available = cls && enableDepth && disableDepth && depthMask && enableTexture2D && disableTexture2D;
    }
}

namespace shadow {
    static jfieldID gameSettingsField = nullptr;
    static jfieldID entityShadowsField = nullptr;
    static bool resolved = false;
    static bool available = false;

    void resolve(JNIEnv* env) {
        if (resolved) return;
        resolved = true;

        gameSettingsField = Mappings::getInstance().getField("Minecraft#gameSettings");
        entityShadowsField = Mappings::getInstance().getField("GameSettings#entityShadows");
        if (env->ExceptionCheck()) { env->ExceptionClear(); }

        available = gameSettingsField && entityShadowsField;
    }

    bool disable(JNIEnv* env, jobject mcObj) {
        if (!available) return true;
        jobject gs = env->GetObjectField(mcObj, gameSettingsField);
        if (!gs) return true;
        bool orig = env->GetBooleanField(gs, entityShadowsField);
        env->SetBooleanField(gs, entityShadowsField, (jboolean)false);
        env->DeleteLocalRef(gs);
        return orig;
    }

    void restore(JNIEnv* env, jobject mcObj, bool orig) {
        if (!available) return;
        jobject gs = env->GetObjectField(mcObj, gameSettingsField);
        if (!gs) return;
        env->SetBooleanField(gs, entityShadowsField, (jboolean)orig);
        env->DeleteLocalRef(gs);
    }
}

namespace {
    jclass clsEntityPlayer     = nullptr;
    jclass clsEntityMob        = nullptr;
    jclass clsEntityAnimal     = nullptr;
    jclass clsEntityVillager   = nullptr;
    jclass clsEntityArmorStand = nullptr;
    bool   classesResolved     = false;

    jclass findGlobal(JNIEnv* env, const char* name) {
        jclass local = env->FindClass(name);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
        if (!local) return nullptr;
        auto global = static_cast<jclass>(env->NewGlobalRef(local));
        env->DeleteLocalRef(local);
        return global;
    }

    jclass clsEntityLivingBase = nullptr;

    void resolveClasses(JNIEnv* env) {
        if (classesResolved) return;

        auto& maps = Mappings::getInstance();
        clsEntityLivingBase = maps.getClass("EntityLivingBase");
        if (!clsEntityLivingBase) clsEntityLivingBase = findGlobal(env, "net/minecraft/entity/EntityLivingBase");
        clsEntityPlayer     = maps.getClass("EntityPlayer");
        if (!clsEntityPlayer)     clsEntityPlayer     = findGlobal(env, "net/minecraft/entity/player/EntityPlayer");
        clsEntityMob        = maps.getClass("EntityMob");
        if (!clsEntityMob)        clsEntityMob        = findGlobal(env, "net/minecraft/entity/monster/EntityMob");
        clsEntityAnimal     = maps.getClass("EntityAnimal");
        if (!clsEntityAnimal)     clsEntityAnimal     = findGlobal(env, "net/minecraft/entity/passive/EntityAnimal");
        clsEntityVillager   = maps.getClass("EntityVillager");
        if (!clsEntityVillager)   clsEntityVillager   = findGlobal(env, "net/minecraft/entity/passive/EntityVillager");
        clsEntityArmorStand = maps.getClass("EntityArmorStand");
        if (!clsEntityArmorStand) clsEntityArmorStand = findGlobal(env, "net/minecraft/entity/item/EntityArmorStand");
        classesResolved = true;
    }

    bool wants(const std::vector<bool>& filter, size_t idx) {
        return idx < filter.size() && filter[idx];
    }
}

ChamsModule::ChamsModule(BindType bindType, int keyCode)
    : Render3dBaseModule(bindType, keyCode) {}

void ChamsModule::onLoad() {
    Render3dBaseModule::onLoad();
    MULTI_COMBO_SETTING(entitiesFilter,
        "Players", "Mobs", "Animals", "Villager", "ArmorStands", "Invisible");
    BOOL_SETTING(renderTexture, false);
    BOOL_SETTING(glowMode, false);
    BOOL_SETTING(hideFriends, false);
    COLOR_SETTING(colorFriend, ImColor(0.0f, 1.0f, 0.0f, 0.39f));
    COLOR_SETTING(colorNeutral, ImColor(1.0f, 1.0f, 1.0f, 0.39f));
}

void ChamsModule::onEnable() { Render3dBaseModule::onEnable(); }
void ChamsModule::onDisable() { Render3dBaseModule::onDisable(); }

void ChamsModule::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    gsm::resolve(env);
    shadow::resolve(env);
    resolveClasses(env);
    resolveGlActiveTexture();

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    auto screen = mc.currentScreen();
    if (!screen.isNull()) { screen.setDeleteRef(false); return; }

    auto player = mc.thePlayer();
    if (player.isNull()) return;
    auto world = mc.theWorld();
    if (world.isNull()) return;
    RenderManager renderManager = mc.getRenderManager();
    if (renderManager.isNull()) return;

    float partialTicks = 0.0f;
    {
        static jfieldID timerField = nullptr;
        static jfieldID rptField   = nullptr;
        if (!timerField) timerField = Mappings::getInstance().getField("Minecraft#timer");
        if (!rptField)   rptField   = Mappings::getInstance().getField("Timer#renderPartialTicks");
        if (timerField && rptField) {
            jobject timer = env->GetObjectField(mc.getObj(), timerField);
            if (timer) {
                partialTicks = env->GetFloatField(timer, rptField);
                env->DeleteLocalRef(timer);
            }
        }
    }

    ArrayList entityList = world.loadedEntityList();
    if (entityList.isNull()) return;

    ActiveRenderInfo2 activeRenderInfo = ActiveRenderInfo2::getInstance(env);
    std::array<double, 16> modelView{};
    std::array<double, 16> projection{};
    activeRenderInfo.getModelView(modelView);
    activeRenderInfo.getProjection(projection);

    int count = entityList.size();
    const float r = colorNeutral.Value.x;
    const float g = colorNeutral.Value.y;
    const float b = colorNeutral.Value.z;
    const float a = colorNeutral.Value.w;

    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadMatrixd(projection.data());
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadMatrixd(modelView.data());

    if (gsm::available) {

    } else {

        glPushAttrib(GL_ALL_ATTRIB_BITS);
        glDepthRange(0.02, 1.0);
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        glDisable(0x0B60);

        bool origShadows = shadow::disable(env, mc.getObj());

        isRenderingChams = true;

        for (int i = 0; i < count; i++) {
            JavaObject entityObj = entityList.get(i);
            if (entityObj.isNull()) continue;

            jobject eObj = entityObj.getObj();

            if (clsEntityLivingBase && !env->IsInstanceOf(eObj, clsEntityLivingBase)) continue;
            if (env->IsSameObject(eObj, player.getObj())) continue;
            { auto* ab = AntiBotModule::getInstancePtr(); if (ab && ab->isBot(env, eObj)) continue; }

            if (hideFriends) {
                if (!friendsModule) friendsModule = static_cast<FriendsModule*>(ModuleHandler::getInstance().getModule<ModuleType::FRIENDS>());
                if (friendsModule) {
                    Entity ent(env, eObj);
                    ent.setDeleteRef(false);
                    if (friendsModule->isFriend(ent)) continue;
                }
            }

            bool passes = false;
            if (clsEntityPlayer && env->IsInstanceOf(eObj, clsEntityPlayer))
                passes = wants(entitiesFilter, 0);
            else if (clsEntityMob && env->IsInstanceOf(eObj, clsEntityMob))
                passes = wants(entitiesFilter, 1);
            else if (clsEntityAnimal && env->IsInstanceOf(eObj, clsEntityAnimal))
                passes = wants(entitiesFilter, 2);
            else if (clsEntityVillager && env->IsInstanceOf(eObj, clsEntityVillager))
                passes = wants(entitiesFilter, 3);
            else if (clsEntityArmorStand && env->IsInstanceOf(eObj, clsEntityArmorStand))
                passes = wants(entitiesFilter, 4);
            if (!passes) continue;

            auto entity = entityObj.convertTo<EntityPlayer>();
            if (entity.isNull() || entity.isDead()) continue;
            if (entity.isInvisible() && !wants(entitiesFilter, 5)) continue;

            glDepthRange(0.02, 1.0);
            glColor4f(1.0f, 1.0f, 1.0f, 1.0f);

            float envColor[4] = { r, g, b, a };
            {
                if (!enemiesModule) enemiesModule = static_cast<EnemiesModule*>(ModuleHandler::getInstance().getModule<ModuleType::ENEMY>());
                Entity ent(env, entity.getObj());
                ent.setDeleteRef(false);
                if (friendsModule && friendsModule->isFriend(ent)) {
                    envColor[0] = colorFriend.Value.x; envColor[1] = colorFriend.Value.y;
                    envColor[2] = colorFriend.Value.z; envColor[3] = colorFriend.Value.w;
                } else {
                    bool isEnemy = false;
                    if (enemiesModule) {
                        JavaUUID uuid = entity.getEntityUniqueID();
                        if (!uuid.isNull()) {
                            UUIDData ud = uuid.toUUIDData();
                            for (const auto& eu : enemiesModule->getEnemyUUIDEntities()) {
                                if (ud.equals(eu)) { isEnemy = true; break; }
                            }
                        }
                    }
                    if (!isEnemy) {
                        envColor[0] = colorNeutral.Value.x; envColor[1] = colorNeutral.Value.y;
                        envColor[2] = colorNeutral.Value.z; envColor[3] = colorNeutral.Value.w;
                    }
                }
            }

            if (glowMode) {
                glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
                renderManager.renderEntitySimple(entity, partialTicks);
                if (env->ExceptionCheck()) env->ExceptionClear();
            } else if (renderTexture) {
                glDisable(GL_LIGHTING);
                glColor4f(1.0f, 1.0f, 1.0f, 1.0f);

                glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
                glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_MODULATE);
                glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB, GL_TEXTURE);
                glTexEnvi(GL_TEXTURE_ENV, 0x8581, GL_CONSTANT_TEX);
                glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_REPLACE);
                glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA, GL_CONSTANT_TEX);
                glTexEnvfv(GL_TEXTURE_ENV, GL_TEXTURE_ENV_COLOR, envColor);

                renderManager.renderEntitySimple(entity, partialTicks);
                if (env->ExceptionCheck()) env->ExceptionClear();

                glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
                glEnable(GL_LIGHTING);
                glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
            } else {
                glDisable(GL_LIGHTING);
                glColor4f(envColor[0], envColor[1], envColor[2], envColor[3]);

                glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
                glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_REPLACE);
                glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB, GL_CONSTANT_TEX);
                glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_REPLACE);
                glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA, GL_TEXTURE);
                glTexEnvfv(GL_TEXTURE_ENV, GL_TEXTURE_ENV_COLOR, envColor);

                renderManager.renderEntitySimple(entity, partialTicks);
                if (env->ExceptionCheck()) env->ExceptionClear();

                glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
                glEnable(GL_LIGHTING);
                glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
            }
        }

        isRenderingChams = false;
        shadow::restore(env, mc.getObj(), origShadows);

        glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
        glDepthRange(0.0, 1.0);

        glPopAttrib();
    }

    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();
    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
}

void ChamsModule::getColorForEntity(JNIEnv* env, jobject entityObj, float outColor[4]) const {
    outColor[0] = colorNeutral.Value.x;
    outColor[1] = colorNeutral.Value.y;
    outColor[2] = colorNeutral.Value.z;
    outColor[3] = colorNeutral.Value.w;

    auto* self = const_cast<ChamsModule*>(this);
    if (!self->friendsModule) self->friendsModule = static_cast<FriendsModule*>(ModuleHandler::getInstance().getModule<ModuleType::FRIENDS>());
    if (!self->enemiesModule) self->enemiesModule = static_cast<EnemiesModule*>(ModuleHandler::getInstance().getModule<ModuleType::ENEMY>());

    if (friendsModule && friendsModule->enable) {
        Entity ent(env, entityObj);
        ent.setDeleteRef(false);
        if (friendsModule->isFriend(ent)) {
            outColor[0] = colorFriend.Value.x;
            outColor[1] = colorFriend.Value.y;
            outColor[2] = colorFriend.Value.z;
            outColor[3] = colorFriend.Value.w;
            return;
        }
    }

    if (enemiesModule && enemiesModule->enable) {
        Entity ent(env, entityObj);
        ent.setDeleteRef(false);
        JavaUUID uuid = ent.getEntityUniqueID();
        if (!uuid.isNull()) {
            UUIDData ud = uuid.toUUIDData();
            for (const auto& eu : enemiesModule->getEnemyUUIDEntities()) {
                if (ud.equals(eu)) return;
            }
        }
    }
}

bool ChamsModule::passesEntityFilter(JNIEnv* env, jobject entityObj) const {
    if (!env || !entityObj) return false;
    resolveClasses(env);

    if (clsEntityPlayer && env->IsInstanceOf(entityObj, clsEntityPlayer))
        return wants(entitiesFilter, 0);
    if (clsEntityMob && env->IsInstanceOf(entityObj, clsEntityMob))
        return wants(entitiesFilter, 1);
    if (clsEntityAnimal && env->IsInstanceOf(entityObj, clsEntityAnimal))
        return wants(entitiesFilter, 2);
    if (clsEntityVillager && env->IsInstanceOf(entityObj, clsEntityVillager))
        return wants(entitiesFilter, 3);
    if (clsEntityArmorStand && env->IsInstanceOf(entityObj, clsEntityArmorStand))
        return wants(entitiesFilter, 4);
    return false;
}

void ChamsModule::renderChamsOverlay(JNIEnv* env) {
    if (!env) return;

    gsm::resolve(env);
    shadow::resolve(env);
    resolveClasses(env);
    resolveGlActiveTexture();

    if (!gsm::available) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) return;

    auto screen = mc.currentScreen();
    if (!screen.isNull()) { screen.setDeleteRef(false); return; }

    auto player = mc.thePlayer();
    if (player.isNull()) return;
    auto world = mc.theWorld();
    if (world.isNull()) return;
    RenderManager renderManager = mc.getRenderManager();
    if (renderManager.isNull()) return;

    float partialTicks = 0.0f;
    {
        static jfieldID timerField = nullptr;
        static jfieldID rptField   = nullptr;
        if (!timerField) timerField = Mappings::getInstance().getField("Minecraft#timer");
        if (!rptField)   rptField   = Mappings::getInstance().getField("Timer#renderPartialTicks");
        if (timerField && rptField) {
            jobject timer = env->GetObjectField(mc.getObj(), timerField);
            if (timer) {
                partialTicks = env->GetFloatField(timer, rptField);
                env->DeleteLocalRef(timer);
            }
        }
    }

    ArrayList entityList = world.loadedEntityList();
    if (entityList.isNull()) return;

    ActiveRenderInfo2 activeRenderInfo = ActiveRenderInfo2::getInstance(env);
    std::array<double, 16> modelView{};
    std::array<double, 16> projection{};
    activeRenderInfo.getModelView(modelView);
    activeRenderInfo.getProjection(projection);

    int count = entityList.size();
    const float r = colorNeutral.Value.x;
    const float g = colorNeutral.Value.y;
    const float b = colorNeutral.Value.z;
    const float a = colorNeutral.Value.w;

    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadMatrixd(projection.data());
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadMatrixd(modelView.data());

    glDepthRange(0.02, 1.0);
    env->CallStaticVoidMethod(gsm::cls, gsm::enableBlend);
    if (gsm::tryBlendFuncSeparate)
        env->CallStaticVoidMethod(gsm::cls, gsm::tryBlendFuncSeparate, 770, 771, 1, 0);
    env->CallStaticVoidMethod(gsm::cls, gsm::disableFog);

    bool origShadows = shadow::disable(env, mc.getObj());

    isRenderingChams = true;

    for (int i = 0; i < count; i++) {
        JavaObject entityObj = entityList.get(i);
        if (entityObj.isNull()) continue;

        jobject eObj = entityObj.getObj();

        if (clsEntityLivingBase && !env->IsInstanceOf(eObj, clsEntityLivingBase)) continue;
        if (env->IsSameObject(eObj, player.getObj())) continue;
        { auto* ab = AntiBotModule::getInstancePtr(); if (ab && ab->isBot(env, eObj)) continue; }

        if (hideFriends) {
            if (!friendsModule) friendsModule = static_cast<FriendsModule*>(ModuleHandler::getInstance().getModule<ModuleType::FRIENDS>());
            if (friendsModule) {
                Entity ent(env, eObj);
                ent.setDeleteRef(false);
                if (friendsModule->isFriend(ent)) continue;
            }
        }

        bool passes = false;
        if (clsEntityPlayer && env->IsInstanceOf(eObj, clsEntityPlayer))
            passes = wants(entitiesFilter, 0);
        else if (clsEntityMob && env->IsInstanceOf(eObj, clsEntityMob))
            passes = wants(entitiesFilter, 1);
        else if (clsEntityAnimal && env->IsInstanceOf(eObj, clsEntityAnimal))
            passes = wants(entitiesFilter, 2);
        else if (clsEntityVillager && env->IsInstanceOf(eObj, clsEntityVillager))
            passes = wants(entitiesFilter, 3);
        else if (clsEntityArmorStand && env->IsInstanceOf(eObj, clsEntityArmorStand))
            passes = wants(entitiesFilter, 4);
        if (!passes) continue;

        auto entity = entityObj.convertTo<EntityPlayer>();
        if (entity.isNull() || entity.isDead()) continue;
        if (entity.isInvisible() && !wants(entitiesFilter, 5)) continue;

        glDepthRange(0.02, 1.0);
        env->CallStaticVoidMethod(gsm::cls, gsm::color, 1.0f, 1.0f, 1.0f, 1.0f);

        float envColor[4] = { r, g, b, a };
        {
            if (!enemiesModule) enemiesModule = static_cast<EnemiesModule*>(ModuleHandler::getInstance().getModule<ModuleType::ENEMY>());
            Entity ent(env, entity.getObj());
            ent.setDeleteRef(false);
            if (friendsModule && friendsModule->isFriend(ent)) {
                envColor[0] = colorFriend.Value.x; envColor[1] = colorFriend.Value.y;
                envColor[2] = colorFriend.Value.z; envColor[3] = colorFriend.Value.w;
            } else {
                bool isEnemy = false;
                if (enemiesModule) {
                    JavaUUID uuid = entity.getEntityUniqueID();
                    if (!uuid.isNull()) {
                        UUIDData ud = uuid.toUUIDData();
                        for (const auto& eu : enemiesModule->getEnemyUUIDEntities()) {
                            if (ud.equals(eu)) { isEnemy = true; break; }
                        }
                    }
                }
                if (!isEnemy) {
                    envColor[0] = colorNeutral.Value.x; envColor[1] = colorNeutral.Value.y;
                    envColor[2] = colorNeutral.Value.z; envColor[3] = colorNeutral.Value.w;
                }
            }
        }

        if (glowMode) {
            env->CallStaticVoidMethod(gsm::cls, gsm::color, 1.0f, 1.0f, 1.0f, 1.0f);
            renderManager.renderEntitySimple(entity, partialTicks);
            if (env->ExceptionCheck()) env->ExceptionClear();
        } else if (renderTexture) {
            env->CallStaticVoidMethod(gsm::cls, gsm::disableLighting);
            glDisable(GL_LIGHTING);
            env->CallStaticVoidMethod(gsm::cls, gsm::color, 1.0f, 1.0f, 1.0f, 1.0f);

            glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
            glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_MODULATE);
            glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB, GL_TEXTURE);
            glTexEnvi(GL_TEXTURE_ENV, 0x8581, GL_CONSTANT_TEX);
            glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_REPLACE);
            glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA, GL_CONSTANT_TEX);
            glTexEnvfv(GL_TEXTURE_ENV, GL_TEXTURE_ENV_COLOR, envColor);

            renderManager.renderEntitySimple(entity, partialTicks);
            if (env->ExceptionCheck()) env->ExceptionClear();

            glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
            glEnable(GL_LIGHTING);
            glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
        } else {
            env->CallStaticVoidMethod(gsm::cls, gsm::enableLighting);
            glDisable(GL_LIGHTING);
            env->CallStaticVoidMethod(gsm::cls, gsm::color, 1.0f, 1.0f, 1.0f, 1.0f);
            glColor4f(envColor[0], envColor[1], envColor[2], envColor[3]);

            glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
            glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_REPLACE);
            glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB, GL_CONSTANT_TEX);
            glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_REPLACE);
            glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA, GL_TEXTURE);
            glTexEnvfv(GL_TEXTURE_ENV, GL_TEXTURE_ENV_COLOR, envColor);

            renderManager.renderEntitySimple(entity, partialTicks);
            if (env->ExceptionCheck()) env->ExceptionClear();

            glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
            glEnable(GL_LIGHTING);
            glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
        }
    }

    isRenderingChams = false;
    shadow::restore(env, mc.getObj(), origShadows);

    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);

    glDepthRange(0.0, 1.0);
    env->CallStaticVoidMethod(gsm::cls, gsm::enableDepth);
    env->CallStaticVoidMethod(gsm::cls, gsm::depthFunc, (jint)515);
    env->CallStaticVoidMethod(gsm::cls, gsm::enableTexture2D);
    env->CallStaticVoidMethod(gsm::cls, gsm::enableLighting);
    env->CallStaticVoidMethod(gsm::cls, gsm::enableAlpha);
    env->CallStaticVoidMethod(gsm::cls, gsm::disableBlend);
    env->CallStaticVoidMethod(gsm::cls, gsm::color, 1.0f, 1.0f, 1.0f, 1.0f);
    env->CallStaticVoidMethod(gsm::cls, gsm::enableCull);
    if (env->ExceptionCheck()) env->ExceptionClear();

    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();
    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
}

REGISTER_MODULE(ChamsModule, ModuleType::CHAMS)
