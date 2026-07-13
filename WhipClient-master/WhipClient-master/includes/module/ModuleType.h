#pragma once

#include "util/ClientStrings.h"

enum class ModuleType {
    NONE,

    AIM_ASSIST,
    ANTI_BOT,
    AUTOCLICKER,
    AUTO_REFILL,
    BACKTRACK,
    BLOCK_HIT,
    CRITICALS,
    KEEP_SPRINT,
    LAG_RANGE,
    PIERCING,
    SMART_CLICKING,
    THROW_MODULE,
    VELOCITY,

    BLINK,

    AUTO_CLUTCH,
    AUTO_SCROLL,
    AUTO_TOOL,
    BOW_BOOST,
    CHEST_STEALER,
    INVMANAGER,
    FAST_BREAK,
    FAST_PLACE,
    NO_C07,
    NO_ITEM_RELEASE,
    POT_COUNTER,
    RIGHT_CLICKER,
    THROW_ROD,
    TICK_LOCKER,

    BRIDGE_ASSIST,
    INV_WALK,
    NO_JUMP_DELAY,
    QUICK_ACCEL,
    NO_SLOW,
    SCAFFOLD,
    SNAP_TAP,
    FAST_STOP,
    SPRINT,
    SPRINT_RESET,

    FULL_BRIGHT,
    FRIENDS,
    ENEMY,
    GUI,
    SETTINGS,
    WEAPONS,

    PRIVATE_CONFIG,
    PUBLIC_CONFIG,

    ARRAYLIST,
    ESP,
    HIT_HEAL_COUNTER,
    WATERMARK,
    STORAGE_ESP,
    CHAMS,
    BLOCK_ESP,
    HUD,
    NAMETAG,
    NOTIFICATION,
    TRACER,
    TRAJECTORIES,
    ITEM_ESP,
    PLAYER_ESP,

    TICK_LOCKER_VISUAL,
    AIM_ASSIST_VISUAL,

    MODULE_COUNT
};

inline const char* toName(ModuleType type) {
    switch (type) {
        case ModuleType::NONE:              return Strings::modNone();

        case ModuleType::AIM_ASSIST:        return Strings::modAimAssist();
        case ModuleType::ANTI_BOT:          return Strings::modAntiBot();
        case ModuleType::AUTOCLICKER:       return Strings::modAutoClicker();
        case ModuleType::AUTO_REFILL:       return Strings::modAutoRefill();
        case ModuleType::BACKTRACK:         return Strings::modBacktrack();
        case ModuleType::BLOCK_HIT:         return Strings::modBlockHit();
        case ModuleType::CRITICALS:         return Strings::modCriticals();
        case ModuleType::KEEP_SPRINT:       return Strings::modKeepSprint();
        case ModuleType::LAG_RANGE:         return Strings::modLagRange();
        case ModuleType::PIERCING:          return Strings::modPiercing();
        case ModuleType::SMART_CLICKING:    return Strings::modSmartClicking();
        case ModuleType::THROW_MODULE:      return Strings::modThrow();
        case ModuleType::VELOCITY:          return Strings::modVelocity();
        case ModuleType::BLINK:             return Strings::modBlink();

        case ModuleType::AUTO_CLUTCH:       return Strings::modAutoClutch();
        case ModuleType::AUTO_SCROLL:      return Strings::modAutoScroll();
        case ModuleType::AUTO_TOOL:         return Strings::modAutoTool();
        case ModuleType::BOW_BOOST:         return Strings::modBowBoost();
        case ModuleType::CHEST_STEALER:     return Strings::modChestStealer();
        case ModuleType::INVMANAGER:        return Strings::modInvManager();
        case ModuleType::FAST_BREAK:        return Strings::modFastBreak();
        case ModuleType::FAST_PLACE:        return Strings::modFastPlace();
        case ModuleType::NO_C07:            return Strings::modNoC07();
        case ModuleType::NO_ITEM_RELEASE:   return Strings::modNoItemRelease();
        case ModuleType::POT_COUNTER:       return Strings::modPotCounter();
        case ModuleType::RIGHT_CLICKER:     return Strings::modRightClicker();
        case ModuleType::THROW_ROD:         return Strings::modThrowRod();
        case ModuleType::TICK_LOCKER:       return Strings::modTickLocker();

        case ModuleType::BRIDGE_ASSIST:     return Strings::modBridgeAssist();
        case ModuleType::INV_WALK:          return Strings::modInvWalk();
        case ModuleType::NO_JUMP_DELAY:     return Strings::modNoJumpDelay();
        case ModuleType::QUICK_ACCEL:       return Strings::modQuickAccel();
        case ModuleType::NO_SLOW:           return Strings::modNoSlow();
        case ModuleType::SCAFFOLD:          return Strings::modScaffold();
        case ModuleType::SNAP_TAP:          return Strings::modSnapTap();
        case ModuleType::FAST_STOP:         return Strings::modFastStop();
        case ModuleType::SPRINT:            return Strings::modSprint();
        case ModuleType::SPRINT_RESET:      return Strings::modSprintReset();

        case ModuleType::FULL_BRIGHT:       return Strings::modFullBright();
        case ModuleType::FRIENDS:           return Strings::modFriends();
        case ModuleType::ENEMY:             return Strings::modEnemies();
        case ModuleType::GUI:               return Strings::modGUI();
        case ModuleType::SETTINGS:          return Strings::modSettings();
        case ModuleType::WEAPONS:           return Strings::modWeapons();

        case ModuleType::PRIVATE_CONFIG:    return Strings::modPrivate();
        case ModuleType::PUBLIC_CONFIG:     return Strings::modPublic();

        case ModuleType::ARRAYLIST:         return Strings::modArrayList();
        case ModuleType::HIT_HEAL_COUNTER:  return Strings::modHitHealCounter();
        case ModuleType::WATERMARK:         return Strings::modWatermark();
        case ModuleType::ESP:               return Strings::modESP();
        case ModuleType::STORAGE_ESP:       return Strings::modStorageESP();
        case ModuleType::CHAMS:             return Strings::modChams();
        case ModuleType::BLOCK_ESP:         return Strings::modBlockESP();
        case ModuleType::HUD:               return Strings::modHUD();
        case ModuleType::NAMETAG:           return Strings::modNameTag();
        case ModuleType::NOTIFICATION:      return Strings::modNotification();
        case ModuleType::TICK_LOCKER_VISUAL: return Strings::modTickLockerVisual();
        case ModuleType::TRACER:            return Strings::modTracer();
        case ModuleType::TRAJECTORIES:     return Strings::modTrajectories();
        case ModuleType::ITEM_ESP:          return Strings::modItemESP();
        case ModuleType::PLAYER_ESP:        return Strings::modPlayerESP();

        case ModuleType::MODULE_COUNT:      return Strings::modInvalid();
        default:                            return Strings::catUnknown();
    }
}
