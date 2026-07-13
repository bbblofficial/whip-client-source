#pragma once

#include <whipnexus/Types.h>

namespace BuildConfig {
    enum class Mode { Local, Dev, Production };

#if defined(WHIP_LOCAL_MODE)
    constexpr Mode mode = Mode::Local;
#elif defined(WHIP_DEV_MODE)
    constexpr Mode mode = Mode::Dev;
#else
    constexpr Mode mode = Mode::Production;
#endif

    constexpr bool isLocal()      { return mode == Mode::Local; }
    constexpr bool isDev()        { return mode == Mode::Dev; }
    constexpr bool isProduction() { return mode == Mode::Production; }

    // Le serveur écoute sur 7777 en prod, 7778 en dev/local
    constexpr u16 serverPort = (mode == Mode::Production) ? 7777 : 7778;

    // En mode local, on lit la DLL côté disque au lieu de la télécharger
    constexpr bool downloadDllFromServer = (mode != Mode::Local);
}
