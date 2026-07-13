#include "module/impl/visual/TrajectoriesModule.h"
#include "wrapper/minecraft/client/Minecraft.h"
#include "wrapper/minecraft/entity/Entity.h"
#include "wrapper/minecraft/entity/EntityLivingBase.h"
#include "wrapper/minecraft/entity/player/EntityPlayer.h"
#include "wrapper/minecraft/entity/player/inventoryplayer.h"
#include "wrapper/minecraft/entity/render/RenderManager.h"
#include "wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo.h"
#include "wrapper/minecraft/item/ItemStack.h"
#include "wrapper/minecraft/world/World.h"
#include "wrapper/minecraft/util/Vec3.h"
#include "wrapper/minecraft/util/MovingObjectPosition.h"
#include "wrapper/java/util/ArrayList.h"
#include "setting/SettingMacros.h"
#include "util/RenderUtils.h"

#include <windows.h>
#include <gl/GL.h>
#include <cmath>
#include <algorithm>

#ifndef GL_ALL_ATTRIB_BITS
#define GL_ALL_ATTRIB_BITS 0x000FFFFF
#endif
#ifndef GL_LINE_STRIP
#define GL_LINE_STRIP 0x0003
#endif
#ifndef GL_LINE_SMOOTH
#define GL_LINE_SMOOTH 0x0B20
#endif
#ifndef GL_LIGHTING
#define GL_LIGHTING 0x0B50
#endif
#ifndef GL_TEXTURE_2D
#define GL_TEXTURE_2D 0x0DE1
#endif
#ifndef GL_QUADS
#define GL_QUADS 0x0007
#endif

static constexpr float DEG2RAD   = 3.14159265358979323846f / 180.0f;
static constexpr int   MAX_STEPS = 300;

namespace {
    float computeBowCharge(int remaining) {
        if (remaining <= 0) return 1.0f;
        int chargeTime = 72000 - remaining;
        float f = static_cast<float>(chargeTime) / 20.0f;
        f = (f * f + f * 2.0f) / 3.0f;
        return std::clamp(f, 0.0f, 1.0f);
    }

    bool rayIntersectsAABB(double ox, double oy, double oz,
                           double dx, double dy, double dz,
                           double minX, double minY, double minZ,
                           double maxX, double maxY, double maxZ,
                           double& tOut) {
        double tmin = 0.0, tmax = 1.0;
        auto slab = [&](double o, double d, double lo, double hi) -> bool {
            if (std::abs(d) < 1e-9) return (o >= lo && o <= hi);
            double t1 = (lo - o) / d, t2 = (hi - o) / d;
            if (t1 > t2) std::swap(t1, t2);
            tmin = std::max(tmin, t1);
            tmax = std::min(tmax, t2);
            return tmin <= tmax;
        };
        if (!slab(ox, dx, minX, maxX)) return false;
        if (!slab(oy, dy, minY, maxY)) return false;
        if (!slab(oz, dz, minZ, maxZ)) return false;
        tOut = tmin;
        return true;
    }
}

TrajectoriesModule::TrajectoriesModule(BindType bindType, int keyCode)
    : Render3dBaseModule(bindType, keyCode) {}

void TrajectoriesModule::onLoad() {
    Render3dBaseModule::onLoad();
    MULTI_COMBO_SETTING(projectileFilter,
        "Bow", "Potion", "Pearl", "Snowball", "Egg", "Rod");
    FLOAT_SLIDER(lineWidth, 2.0f, 1.0f, 8.0f);
    COLOR_SETTING(arcColor, ImColor(0.08f, 0.47f, 0.90f, 0.85f));
}

void TrajectoriesModule::onEnable() { Render3dBaseModule::onEnable(); }
void TrajectoriesModule::onDisable() { points_.clear(); hitEntity_.valid = false; Render3dBaseModule::onDisable(); }

void TrajectoriesModule::onRender3d(const Render3dEvent& event) {
    JNIEnv* env = event.getEnv();
    if (!env) return;

    if (env->PushLocalFrame(512) < 0) return;

    Minecraft mc = Minecraft::getMinecraft(env);
    if (mc.isNull()) { env->PopLocalFrame(nullptr); return; }

    auto screen = mc.currentScreen();
    if (!screen.isNull()) { screen.setDeleteRef(false); points_.clear(); hitEntity_.valid = false; env->PopLocalFrame(nullptr); return; }

    auto player = mc.thePlayer();
    if (player.isNull()) { env->PopLocalFrame(nullptr); return; }
    InventoryPlayer inv = player.inventoryPlayer();
    if (inv.isNull()) { env->PopLocalFrame(nullptr); return; }
    inv.setDeleteRef(false);

    ItemStack held = inv.getItem(inv.currentItem());
    if (held.isNull()) { points_.clear(); hitEntity_.valid = false; env->PopLocalFrame(nullptr); return; }

    ProjectileType projType = ProjectileType::NONE;
    int filterIdx = -1;
    if      (held.isPunch())                              { projType = ProjectileType::BOW;         filterIdx = 0; }
    else if (held.isPotion() && (held.metadata() & 0x4000)) { projType = ProjectileType::POTION;     filterIdx = 1; }
    else if (held.IsPearl())                              { projType = ProjectileType::ENDER_PEARL; filterIdx = 2; }
    else if (held.isSnowball())                           { projType = ProjectileType::SNOWBALL;    filterIdx = 3; }
    else if (held.isEgg())                                { projType = ProjectileType::EGG;         filterIdx = 4; }
    else if (held.isRod())                                { projType = ProjectileType::ROD;         filterIdx = 5; }

    if (projType == ProjectileType::NONE
        || filterIdx < 0
        || filterIdx >= static_cast<int>(projectileFilter.size())
        || !projectileFilter[filterIdx]) {
        points_.clear(); hitEntity_.valid = false; env->PopLocalFrame(nullptr); return;
    }

    float bowCharge = 1.0f;
    if (projType == ProjectileType::BOW) {
        if (!player.isUsingItem()) { points_.clear(); hitEntity_.valid = false; env->PopLocalFrame(nullptr); return; }
        bowCharge = computeBowCharge(player.itemInUseCount());
        if (bowCharge < 0.1f) { points_.clear(); hitEntity_.valid = false; env->PopLocalFrame(nullptr); return; }
    }

    float pt = mc.timer().GetrenderPartialTicks();

    Vec3D cam;
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_8_9) {
        RenderManager rm = mc.getRenderManager();
        if (rm.isNull()) { env->PopLocalFrame(nullptr); return; }
        rm.setDeleteRef(false);
        cam = rm.getRenderPos();
    }
    if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
        RenderManager rm = RenderManager::getInstance(env);
        if (rm.isNull()) { env->PopLocalFrame(nullptr); return; }
        rm.setDeleteRef(false);
        cam = rm.getRenderPos();
    }

    float yaw   = player.prevRotationYaw()   + (player.rotationYaw()   - player.prevRotationYaw())   * pt;
    float pitch = player.prevRotationPitch() + (player.rotationPitch() - player.prevRotationPitch()) * pt;
    float yawR   = yaw   * DEG2RAD;
    float pitchR = pitch * DEG2RAD;

    double posX = player.lastTickPosX() + (player.posX() - player.lastTickPosX()) * pt;
    double posY = player.lastTickPosY() + (player.posY() - player.lastTickPosY()) * pt
                  + static_cast<double>(player.getEyeHeight());
    double posZ = player.lastTickPosZ() + (player.posZ() - player.lastTickPosZ()) * pt;

    posX -= static_cast<double>(std::cos(yawR) * 0.16f);
    posY -= 0.10000000149011612;
    posZ -= static_cast<double>(std::sin(yawR) * 0.16f);

    float pitchOffset = (projType == ProjectileType::POTION) ? -20.0f : 0.0f;
    float sinYaw       = std::sin(yawR);
    float cosYaw       = std::cos(yawR);
    float cosPitch     = std::cos(pitchR);
    float sinPitchOff  = std::sin((pitch + pitchOffset) * DEG2RAD);

    double rawX = static_cast<double>(-sinYaw * cosPitch);
    double rawZ = static_cast<double>( cosYaw * cosPitch);
    double rawY = static_cast<double>(-sinPitchOff);

    double len = std::sqrt(rawX * rawX + rawY * rawY + rawZ * rawZ);
    if (len < 1e-6) { points_.clear(); hitEntity_.valid = false; env->PopLocalFrame(nullptr); return; }

    double speed;
    switch (projType) {
        case ProjectileType::POTION: speed = 0.5;                   break;
        case ProjectileType::BOW:    speed = bowCharge * 2.0 * 1.5; break;
        default:                     speed = 1.5;                   break;
    }

    double vX = (rawX / len) * speed;
    double vY = (rawY / len) * speed;
    double vZ = (rawZ / len) * speed;

    double gravity, drag;
    switch (projType) {
        case ProjectileType::POTION: gravity = 0.05;                drag = 0.99; break;
        case ProjectileType::BOW:    gravity = 0.05;                drag = 0.99; break;
        case ProjectileType::ROD:    gravity = 0.03999999910593033; drag = 0.92; break;
        default:                     gravity = 0.03;                drag = 0.99; break;
    }

    World world = player.worldObj();
    bool hasWorld = !world.isNull();
    if (hasWorld) world.setDeleteRef(false);

    struct EntityAABB {
        double minX, minY, minZ, maxX, maxY, maxZ;
    };
    std::vector<EntityAABB> entityBoxes;
    hitEntity_.valid = false;

    if (hasWorld) {

        ArrayList entityList = world.playerEntities();
        if (!entityList.isNull()) {
            entityList.setDeleteRef(false);
            int count = entityList.size();
            entityBoxes.reserve(std::min(count, 200));

            for (int i = 0; i < count && i < 200; i++) {
                JavaObject rawObj = entityList.get(i);
                if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
                if (rawObj.isNull()) continue;
                rawObj.setDeleteRef(false);

                Entity ent(env, rawObj.getObj());
                ent.setDeleteRef(false);

                if (env->IsSameObject(ent.getObj(), player.getObj())) continue;

                double ex = ent.lastTickPosX() + (ent.posX() - ent.lastTickPosX()) * pt;
                double ey = ent.lastTickPosY() + (ent.posY() - ent.lastTickPosY()) * pt;
                double ez = ent.lastTickPosZ() + (ent.posZ() - ent.lastTickPosZ()) * pt;

                AxisAlignedBB bb = ent.getBoundingBox();
                if (bb.isNull()) continue;
                bb.setDeleteRef(false);

                double halfW = (bb.getMaxX() - bb.getMinX()) * 0.5;
                double height = bb.getMaxY() - bb.getMinY();

                entityBoxes.push_back({
                    ex - halfW, ey,          ez - halfW,
                    ex + halfW, ey + height, ez + halfW
                });
            }
        }
    }

    points_.clear();
    points_.reserve(MAX_STEPS);

    bool hitBlock  = false;
    bool hitEntity = false;
    int  hitEntityIdx = -1;

    static constexpr int SKIP_TICKS = 1;

    for (int i = 0; i < MAX_STEPS; i++) {
        if (i >= SKIP_TICKS) {
            points_.push_back({
                static_cast<float>(posX - cam.x),
                static_cast<float>(posY - cam.y),
                static_cast<float>(posZ - cam.z)
            });
        }

        double nextX = posX + vX;
        double nextY = posY + vY;
        double nextZ = posZ + vZ;

        double segDx = nextX - posX;
        double segDy = nextY - posY;
        double segDz = nextZ - posZ;

        double bestT = 1e9;
        int bestIdx = -1;
        for (int e = 0; e < static_cast<int>(entityBoxes.size()); e++) {
            const auto& eb = entityBoxes[e];
            double t;
            if (rayIntersectsAABB(posX, posY, posZ, segDx, segDy, segDz,
                                  eb.minX, eb.minY, eb.minZ,
                                  eb.maxX, eb.maxY, eb.maxZ, t)) {
                if (t < bestT) { bestT = t; bestIdx = e; }
            }
        }

        if (bestIdx >= 0) {
            double hitX = posX + segDx * bestT;
            double hitY = posY + segDy * bestT;
            double hitZ = posZ + segDz * bestT;
            points_.push_back({
                static_cast<float>(hitX - cam.x),
                static_cast<float>(hitY - cam.y),
                static_cast<float>(hitZ - cam.z)
            });
            hitEntity = true;
            hitEntityIdx = bestIdx;
            break;
        }

        if (hasWorld) {
            Vec3MC from = Vec3MC::createVec3(env, posX, posY, posZ);
            Vec3MC to   = Vec3MC::createVec3(env, nextX, nextY, nextZ);
            from.setDeleteRef(false);
            to.setDeleteRef(false);

            if (!from.isNull() && !to.isNull()) {
                MovingObjectPosition hit = world.rayTraceBlocks(from, to);
                hit.setDeleteRef(false);

                if (!hit.isNull() && hit.typeOfHit() == MovingObjectPosition::TypeOfHit::BLOCK) {
                    Vec3MC hitVec = hit.hitVec();
                    hitVec.setDeleteRef(false);
                    double lx = !hitVec.isNull() ? hitVec.getX() : nextX;
                    double ly = !hitVec.isNull() ? hitVec.getY() : nextY;
                    double lz = !hitVec.isNull() ? hitVec.getZ() : nextZ;

                    points_.push_back({
                        static_cast<float>(lx - cam.x),
                        static_cast<float>(ly - cam.y),
                        static_cast<float>(lz - cam.z)
                    });
                    hitBlock = true;
                    break;
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
        }

        posX = nextX;
        posY = nextY;
        posZ = nextZ;
        vX *= drag;
        vY *= drag;
        vZ *= drag;
        vY -= gravity;

        if (posY < -64.0) break;
    }

    if (hitEntity && hitEntityIdx >= 0) {
        const auto& eb = entityBoxes[hitEntityIdx];
        hitEntity_.valid = true;
        hitEntity_.minX = eb.minX; hitEntity_.minY = eb.minY; hitEntity_.minZ = eb.minZ;
        hitEntity_.maxX = eb.maxX; hitEntity_.maxY = eb.maxY; hitEntity_.maxZ = eb.maxZ;
    } else {
        hitEntity_.valid = false;
    }

    if (points_.size() < 2) { env->PopLocalFrame(nullptr); return; }

    std::vector<float> pj = ActiveRenderInfo::GetProjectionMatrix(env);
    std::vector<float> mv = ActiveRenderInfo::GetModelViewMatrix(env);
    if (pj.size() != 16 || mv.size() != 16) { env->PopLocalFrame(nullptr); return; }

    glPushAttrib(GL_ALL_ATTRIB_BITS);
    glMatrixMode(GL_PROJECTION); glPushMatrix(); glLoadMatrixf(pj.data());
    glMatrixMode(GL_MODELVIEW);  glPushMatrix(); glLoadMatrixf(mv.data());

    glDisable(GL_TEXTURE_2D);
    glDisable(GL_LIGHTING);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glEnable(GL_LINE_SMOOTH);
    glDisable(GL_DEPTH_TEST);
    glDepthMask(GL_FALSE);

    float cr = arcColor.Value.x, cg = arcColor.Value.y;
    float cb = arcColor.Value.z, ca = arcColor.Value.w;

    glLineWidth(lineWidth);
    glColor4f(cr, cg, cb, ca);
    glBegin(GL_LINE_STRIP);
    for (const auto& p : points_) glVertex3f(p.x, p.y, p.z);
    glEnd();

    if (hitBlock) {
        const auto& lp = points_.back();
        constexpr float s = 0.35f;

        glColor4f(cr, cg, cb, ca * 0.4f);
        glBegin(GL_QUADS);
        glVertex3f(lp.x - s, lp.y + 0.01f, lp.z - s);
        glVertex3f(lp.x + s, lp.y + 0.01f, lp.z - s);
        glVertex3f(lp.x + s, lp.y + 0.01f, lp.z + s);
        glVertex3f(lp.x - s, lp.y + 0.01f, lp.z + s);
        glEnd();

        glLineWidth(lineWidth + 1.0f);
        glColor4f(cr, cg, cb, ca);
        glBegin(GL_LINE_STRIP);
        glVertex3f(lp.x - s, lp.y + 0.01f, lp.z - s);
        glVertex3f(lp.x + s, lp.y + 0.01f, lp.z - s);
        glVertex3f(lp.x + s, lp.y + 0.01f, lp.z + s);
        glVertex3f(lp.x - s, lp.y + 0.01f, lp.z + s);
        glVertex3f(lp.x - s, lp.y + 0.01f, lp.z - s);
        glEnd();
    }

    if (hitEntity_.valid) {
        float x0 = static_cast<float>(hitEntity_.minX - cam.x);
        float y0 = static_cast<float>(hitEntity_.minY - cam.y);
        float z0 = static_cast<float>(hitEntity_.minZ - cam.z);
        float x1 = static_cast<float>(hitEntity_.maxX - cam.x);
        float y1 = static_cast<float>(hitEntity_.maxY - cam.y);
        float z1 = static_cast<float>(hitEntity_.maxZ - cam.z);

        glColor4f(cr, cg, cb, 0.15f);
        glBegin(GL_QUADS);
        glVertex3f(x0, y0, z0); glVertex3f(x1, y0, z0); glVertex3f(x1, y0, z1); glVertex3f(x0, y0, z1);
        glVertex3f(x0, y1, z0); glVertex3f(x1, y1, z0); glVertex3f(x1, y1, z1); glVertex3f(x0, y1, z1);
        glVertex3f(x0, y0, z0); glVertex3f(x1, y0, z0); glVertex3f(x1, y1, z0); glVertex3f(x0, y1, z0);
        glVertex3f(x0, y0, z1); glVertex3f(x1, y0, z1); glVertex3f(x1, y1, z1); glVertex3f(x0, y1, z1);
        glVertex3f(x0, y0, z0); glVertex3f(x0, y0, z1); glVertex3f(x0, y1, z1); glVertex3f(x0, y1, z0);
        glVertex3f(x1, y0, z0); glVertex3f(x1, y0, z1); glVertex3f(x1, y1, z1); glVertex3f(x1, y1, z0);
        glEnd();

        glLineWidth(lineWidth);
        glColor4f(cr, cg, cb, ca);
        glBegin(GL_LINES);
        glVertex3f(x0, y0, z0); glVertex3f(x1, y0, z0);
        glVertex3f(x1, y0, z0); glVertex3f(x1, y0, z1);
        glVertex3f(x1, y0, z1); glVertex3f(x0, y0, z1);
        glVertex3f(x0, y0, z1); glVertex3f(x0, y0, z0);
        glVertex3f(x0, y1, z0); glVertex3f(x1, y1, z0);
        glVertex3f(x1, y1, z0); glVertex3f(x1, y1, z1);
        glVertex3f(x1, y1, z1); glVertex3f(x0, y1, z1);
        glVertex3f(x0, y1, z1); glVertex3f(x0, y1, z0);
        glVertex3f(x0, y0, z0); glVertex3f(x0, y1, z0);
        glVertex3f(x1, y0, z0); glVertex3f(x1, y1, z0);
        glVertex3f(x1, y0, z1); glVertex3f(x1, y1, z1);
        glVertex3f(x0, y0, z1); glVertex3f(x0, y1, z1);
        glEnd();
    }

    glMatrixMode(GL_MODELVIEW);  glPopMatrix();
    glMatrixMode(GL_PROJECTION); glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
    glPopAttrib();

    env->PopLocalFrame(nullptr);
}

REGISTER_MODULE(TrajectoriesModule, ModuleType::TRAJECTORIES)
