#pragma once

#include "hook/base/BaseHook.h"
#include "module/impl/visual/ChamsModule.h"
#include "handler/MappingHandler.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include <gl/GL.h>

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
#ifndef GL_LIGHTING
#define GL_LIGHTING 0x0B50
#endif

class RenderEntitySimpleHook final : public StaticBaseHook<RenderEntitySimpleHook> {
    bool m_active = false;
    bool m_origShadowValue = true;
    bool m_modifiedTexEnv = false;

public:

    static inline bool isInChamsHook = false;

    static inline jfieldID s_gameSettingsField = nullptr;
    static inline jfieldID s_shadowField = nullptr;
    static inline bool s_fieldsResolved = false;

    void resolveFields(JNIEnv* env) {
        if (s_fieldsResolved) return;
        s_fieldsResolved = true;
        s_gameSettingsField = Mappings::getInstance().getField("Minecraft#gameSettings");

        s_shadowField = Mappings::getInstance().getField("GameSettings#entityShadows");
        if (!s_shadowField) s_shadowField = Mappings::getInstance().getField("GameSettings#fancyGraphics");
    }

public:
    RenderEntitySimpleHook() : StaticBaseHook(HookPosition::BOTH) {}
    ~RenderEntitySimpleHook() override = default;

    static std::string getHookName() {
        return "RenderManager#renderEntitySimple";
    }

protected:
    HookResult onPreExecute(JNIEnv* env, jobjectArray args) override {
        m_active = false;

        auto* chamsMod = ChamsModule::getInstancePtr();
        if (!chamsMod || !chamsMod->isEnabled()) return HookResult::Continue();

        if (ChamsModule::isRenderingChams) return HookResult::Continue();

        jobject entityObj = getArg(env, args, 1);
        if (!entityObj) return HookResult::Continue();

        static jclass clsEntityLivingBase = nullptr;
        if (!clsEntityLivingBase) {
            clsEntityLivingBase = Mappings::getInstance().getClass("EntityLivingBase");
        }
        if (!clsEntityLivingBase || !env->IsInstanceOf(entityObj, clsEntityLivingBase))
            return HookResult::Continue();

        if (!chamsMod->passesEntityFilter(env, entityObj))
            return HookResult::Continue();

        m_active = true;
        isInChamsHook = true;
        m_modifiedTexEnv = false;

        resolveFields(env);
        m_origShadowValue = true;
        if (s_gameSettingsField && s_shadowField) {
            Minecraft mc = Minecraft::getMinecraft(env);
            if (!mc.isNull()) {
                jobject gs = env->GetObjectField(mc.getObj(), s_gameSettingsField);
                if (gs) {
                    m_origShadowValue = env->GetBooleanField(gs, s_shadowField);
                    env->SetBooleanField(gs, s_shadowField, (jboolean)false);
                    env->DeleteLocalRef(gs);
                }
            }
        }

        glDepthRange(0.0, 0.01);
        glDisable(0x0B60);
        glDisable(GL_LIGHTING);

        if (chamsMod->isGlowMode()) {

            glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
        } else {

            float color[4];
            chamsMod->getColorForEntity(env, entityObj, color);

            m_modifiedTexEnv = true;

            if (chamsMod->isRenderTexture()) {

                glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
                glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_MODULATE);
                glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB, GL_TEXTURE);
                glTexEnvi(GL_TEXTURE_ENV, 0x8581, GL_CONSTANT_TEX);
                glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_REPLACE);
                glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA, GL_TEXTURE);
                glTexEnvfv(GL_TEXTURE_ENV, GL_TEXTURE_ENV_COLOR, color);
            } else {

                glDisable(GL_LIGHTING);
                glColor4f(color[0], color[1], color[2], color[3]);

                glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
                glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_REPLACE);
                glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB, GL_CONSTANT_TEX);
                glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_REPLACE);
                glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA, GL_TEXTURE);
                glTexEnvfv(GL_TEXTURE_ENV, GL_TEXTURE_ENV_COLOR, color);
            }
        }

        return HookResult::Continue();
    }

    void onPostExecute(JNIEnv* env, jobject result, jobjectArray args) override {
        if (!m_active) return;
        m_active = false;
        isInChamsHook = false;

        glDepthRange(0.0, 1.0);
        glEnable(0x0B60);
        glEnable(GL_LIGHTING);

        if (s_gameSettingsField && s_shadowField) {
            Minecraft mc = Minecraft::getMinecraft(env);
            if (!mc.isNull()) {
                jobject gs = env->GetObjectField(mc.getObj(), s_gameSettingsField);
                if (gs) {
                    env->SetBooleanField(gs, s_shadowField, (jboolean)m_origShadowValue);
                    env->DeleteLocalRef(gs);
                }
            }
        }

        if (m_modifiedTexEnv) {
            glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
            glEnable(GL_LIGHTING);
            glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
        }
    }
};
