#pragma once
#include <iostream>

#include "../../../../includes/wrapper/primitive/javaobject.h"
#include "../../../../includes/wrapper/java/util/ArrayList.h"
#include "../entity/axisalignedbb/AxisAlignedBB.h"
#include "../entity/Entity.h"
#include "../entity/player/entityplayer.h"
#include "../../java/util/uuid.h"
#include "../util/BlockPos.h"
#include "../block/state/IBlockstate.h"
#include "../block/Block.h"
#include "../world/border/WorldBorder.h"
#include "chunk/Chunk.h"
#include "wrapper/minecraft/util/MovingObjectPosition.h"
#include "../../../util/MinecraftDetails.h"

class World : public JavaObject {
private:
    static jfieldID playerEntitiesId;
    static jfieldID loadedEntityListId;
    static jmethodID getEntitiesWithinAABBId;
    static jmethodID getEntitiesWithinAABBExcludingEntityId;
    static jmethodID getEntitiesInAABBexcludingId;
    static jmethodID getPlayerEntityByUUIDId;
    static jmethodID getBlockStateId;
    static jmethodID getWorldBorderId;
    static jmethodID getCollidingBoundingBoxesId;
    static jfieldID loadedTileEntityListId;
    static jmethodID getChunkFromChunkCoordsId;
    static jmethodID rayTraceBlocksId;
    static jmethodID rayTraceBlocksFullId;
    static jmethodID getBlockId;
    static jmethodID isAirBlockId;
    static jmethodID isAirBlockBPId;

public:
    World(JNIEnv* env, jobject obj) : JavaObject::JavaObject(env, obj) {}

    ArrayList playerEntities() {
        if (!playerEntitiesId) playerEntitiesId = mappings->getField("World#playerEntities");

        jobject obj = this->env->GetObjectField(this->obj, playerEntitiesId);
        if (!obj) return { NULL, NULL };

        return { this->env, obj };
    }

    ArrayList loadedTileEntityList() {
        if (!loadedTileEntityListId) loadedTileEntityListId = mappings->getField("World#loadedTileEntityList");

        jobject obj = this->env->GetObjectField(this->obj, loadedTileEntityListId);
        if (!obj) return { NULL, NULL };

        return { this->env, obj };
    }

    ArrayList loadedEntityList() {
        if (!loadedEntityListId) loadedEntityListId = mappings->getField("World#loadedEntityList");

        jobject obj = this->env->GetObjectField(this->obj, loadedEntityListId);
        if (!obj) return { NULL, NULL };

        return { this->env, obj };
    }

    EntityPlayer getPlayerEntityByUUID(JavaUUID uuid) {
        if (!getPlayerEntityByUUIDId) getPlayerEntityByUUIDId = mappings->getMethod("World#getPlayerEntityByUUID");

        jobject obj = this->env->CallObjectMethod(this->obj, getPlayerEntityByUUIDId, uuid.getObj());
        if (!obj) return { NULL, NULL };

        return { this->env, obj };
    }

    MovingObjectPosition rayTraceBlocks(const Vec3MC& p_72933_1_, const Vec3MC& p_72933_2_) {
        if (!rayTraceBlocksId) rayTraceBlocksId = mappings->getMethod("World#rayTraceBlocks");

        jobject obj = this->env->CallObjectMethod(this->obj, rayTraceBlocksId,
                                                   p_72933_1_.getObj(),
                                                   p_72933_2_.getObj());
        if (!obj) return { NULL, NULL };

        return { this->env, obj };
    }

    MovingObjectPosition rayTraceBlocksFull(const Vec3MC& from, const Vec3MC& to,
                                            bool stopOnLiquid, bool ignoreBlockWithoutBoundingBox,
                                            bool returnLastUncollidableBlock) {
        if (!rayTraceBlocksFullId) rayTraceBlocksFullId = mappings->getMethod("World#rayTraceBlocks_Vec3_Vec3_Z_Z_Z");
        if (!rayTraceBlocksFullId) return { NULL, NULL };

        jobject obj = this->env->CallObjectMethod(this->obj, rayTraceBlocksFullId,
                                                   from.getObj(),
                                                   to.getObj(),
                                                   (jboolean)stopOnLiquid,
                                                   (jboolean)ignoreBlockWithoutBoundingBox,
                                                   (jboolean)returnLastUncollidableBlock);
        if (!obj) return { NULL, NULL };

        return { this->env, obj };
    }

    Block getBlockAt(int x, int y, int z) {
        if (!this->obj || !this->env) return Block(this->env, NULL);

        if (MinecraftSession::getInstance().version == MinecraftVersion::V1_7_10) {
            if (!getBlockId) getBlockId = mappings->getMethod("World#getBlock");
            if (!getBlockId) return Block(this->env, NULL);

            jobject result = this->env->CallObjectMethod(this->obj, getBlockId, x, y, z);
            if (this->env->ExceptionCheck()) {
                this->env->ExceptionClear();
                return Block(this->env, NULL);
            }
            if (!result) return Block(this->env, NULL);
            return Block(this->env, result);
        }

        BlockPos blockPos = BlockPos::create(this->env, x, y, z);
        if (blockPos.isNull()) return Block(this->env, NULL);

        IBlockState state = getBlockState(blockPos);
        if (state.isNull()) return Block(this->env, NULL);

        return state.getBlock();
    }

    bool isAirBlock(int x, int y, int z) {
        if (!isAirBlockId) isAirBlockId = mappings->getMethod("World#isAirBlock");
        if (!isAirBlockId) return true;

        jboolean result = this->env->CallBooleanMethod(this->obj, isAirBlockId, x, y, z);
        if (this->env->ExceptionCheck()) {
            this->env->ExceptionClear();
            return true;
        }
        return result;
    }

    bool isAirBlock(BlockPos pos) {
        if (pos.isNull()) return true;
        if (!isAirBlockBPId) isAirBlockBPId = mappings->getMethod("World#isAirBlock");
        if (!isAirBlockBPId) return true;

        jboolean result = this->env->CallBooleanMethod(this->obj, isAirBlockBPId, pos.getObj());
        if (this->env->ExceptionCheck()) {
            this->env->ExceptionClear();
            return true;
        }
        return result;
    }

    IBlockState getBlockState(BlockPos blockPos) {
        if (blockPos.isNull()) {
            return IBlockState(env, NULL);
        }

        if (!this->obj) {
            return IBlockState(env, NULL);
        }

        if (!this->env) {
            return IBlockState(env, NULL);
        }

        if (!getBlockStateId) {
            if (!mappings) {
                return IBlockState(env, NULL);
            }

            getBlockStateId = mappings->getMethod("World#getBlockState");

            if (!getBlockStateId) {
                return IBlockState(env, NULL);
            }
        }

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
        }

        jobject result = this->env->CallObjectMethod(this->obj, getBlockStateId, blockPos.getObj());

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
            return IBlockState(env, NULL);
        }

        if (!result) {
            return IBlockState(env, NULL);
        }

        return IBlockState(this->env, result);
    }

    WorldBorder getWorldBorder() {
        if (!this->obj) {
            return WorldBorder(env, NULL);
        }

        if (!this->env) {
            return WorldBorder(env, NULL);
        }

        if (!getWorldBorderId) {
            if (!mappings) {
                return WorldBorder(env, NULL);
            }

            getWorldBorderId = mappings->getMethod("World#getWorldBorder");

            if (!getWorldBorderId) {
                return WorldBorder(env, NULL);
            }
        }

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
        }

        jobject result = this->env->CallObjectMethod(this->obj, getWorldBorderId);

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
            return WorldBorder(env, NULL);
        }

        if (!result) {
            return WorldBorder(env, NULL);
        }

        return WorldBorder(this->env, result);
    }

    ArrayList getCollidingBoundingBoxes(Entity entity, AxisAlignedBB boundingBox) {
        if (entity.isNull()) {
            return ArrayList(env, NULL);
        }

        if (boundingBox.isNull()) {
            return ArrayList(env, NULL);
        }

        if (!this->obj) {
            return ArrayList(env, NULL);
        }

        if (!this->env) {
            return ArrayList(env, NULL);
        }

        if (!getCollidingBoundingBoxesId) {
            if (!mappings) {
                return ArrayList(env, NULL);
            }

            getCollidingBoundingBoxesId = mappings->getMethod("World#getCollidingBoundingBoxes");

            if (!getCollidingBoundingBoxesId) {
                return ArrayList(env, NULL);
            }
        }

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
        }

        jobject result = this->env->CallObjectMethod(this->obj, getCollidingBoundingBoxesId, entity.getObj(), boundingBox.getObj());

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
            return ArrayList(env, NULL);
        }

        if (!result) {
            return ArrayList(env, NULL);
        }

        ArrayList arrayList(this->env, result);

        try {
            int size = arrayList.size();

            if (size > 0 && size <= 10) {
                for (int i = 0; i < size; i++) {
                    JavaObject obj = arrayList.get(i);
                }
            }
            else if (size > 10) {
            }

        }
        catch (const std::exception& e) {
            return ArrayList(env, NULL);
        }
        catch (...) {
            return ArrayList(env, NULL);
        }

        return arrayList;
    }

    ArrayList getEntitiesWithinAABB(jclass entityClass, AxisAlignedBB boundingBox) {

        if (!entityClass) {
            return ArrayList(env, NULL);
        }

        if (boundingBox.isNull()) {
            return ArrayList(env, NULL);
        }

        if (!this->obj) {
            return ArrayList(env, NULL);
        }

        if (!this->env) {
            return ArrayList(env, NULL);
        }

        if (!getEntitiesWithinAABBId) {

            if (!mappings) {
                return ArrayList(env, NULL);
            }

            getEntitiesWithinAABBId = mappings->getMethod("World#getEntitiesWithinAABB");

            if (!getEntitiesWithinAABBId) {
                return ArrayList(env, NULL);
            }
        }

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
        }

        jobject result = this->env->CallObjectMethod(this->obj, getEntitiesWithinAABBId, entityClass, boundingBox.getObj());

        if (this->env->ExceptionCheck()) {
            this->env->ExceptionDescribe();
            this->env->ExceptionClear();
            return ArrayList(env, NULL);
        }

        if (!result) {
            return ArrayList(env, NULL);
        }

        ArrayList arrayList(this->env, result);

        try {
            int size = arrayList.size();

            if (size > 0 && size <= 10) {
                for (int i = 0; i < size; i++) {
                    JavaObject obj = arrayList.get(i);
                }
            }
            else if (size > 10) {
            }

        }
        catch (const std::exception& e) {
            return ArrayList(env, NULL);
        }
        catch (...) {
            return ArrayList(env, NULL);
        }

        return arrayList;
    }

    ArrayList getEntitiesWithinAABBExcludingEntity(Entity& excludedEntity, AxisAlignedBB boundingBox) {
        if (!getEntitiesWithinAABBExcludingEntityId) getEntitiesWithinAABBExcludingEntityId = mappings->getMethod("World#getEntitiesWithinAABBExcludingEntity");

        jobject obj = this->env->CallObjectMethod(this->obj, getEntitiesWithinAABBExcludingEntityId, excludedEntity.getObj(), boundingBox.getObj());
        if (!obj) return { env, nullptr };

        return { this->env, obj };
    }

    Chunk getChunkFromChunkCoords(int chunkX, int chunkZ) {
        if (!getChunkFromChunkCoordsId) getChunkFromChunkCoordsId = mappings->getMethod("World#getChunkFromChunkCoords");

        jobject obj = this->env->CallObjectMethod(this->obj, getChunkFromChunkCoordsId, chunkX, chunkZ);
        if (!obj) return { env, nullptr };

        return { this->env, obj };
    }
};
