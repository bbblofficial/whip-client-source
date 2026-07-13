cmake_minimum_required(VERSION 3.20)
# v1.0.1
project(WhipClient VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT WIN32)
    message(FATAL_ERROR "This project is designed for Windows only")
endif ()

# ─── Build Type ───────────────────────────────────────────────────────────────
set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)

# ─── Whip Build Mode ──────────────────────────────────────────────────────────
# DEV_STANDALONE:     Client seul sans loader (port 7778, mode dev)
# DEV_WITH_LOADER:    Client + loader IPC (port 7778, mode dev)
# PROD_WITH_LOADER:   Client + loader IPC (port 7777, mode prod)
set(WHIP_BUILD_MODE "DEV_STANDALONE" CACHE STRING "Whip build configuration")
set_property(CACHE WHIP_BUILD_MODE PROPERTY STRINGS "DEV_STANDALONE" "DEV_WITH_LOADER" "PROD_WITH_LOADER")

# Apply build mode defines
if(WHIP_BUILD_MODE STREQUAL "DEV_STANDALONE")
    add_compile_definitions(WHIP_DEV_MODE)
    message(STATUS "Whip Build Mode: DEV STANDALONE (Client seul, port 7778)")
elseif(WHIP_BUILD_MODE STREQUAL "DEV_WITH_LOADER")
    add_compile_definitions(LOADER_IPC WHIP_DEV_MODE)
    message(STATUS "Whip Build Mode: DEV WITH LOADER (Client + Loader IPC, port 7778)")
elseif(WHIP_BUILD_MODE STREQUAL "PROD_WITH_LOADER")
    add_compile_definitions(LOADER_IPC WHIP_PRODUCTION)
    message(STATUS "Whip Build Mode: PROD WITH LOADER (Client + Loader IPC, port 7777)")
else()
    message(FATAL_ERROR "Invalid WHIP_BUILD_MODE: ${WHIP_BUILD_MODE}")
endif()

# ─── Options ──────────────────────────────────────────────────────────────────
option(BUILD_WITH_VMPROTECT "Build with VMProtect SDK" ON)

# ─── Compiler Flags ───────────────────────────────────────────────────────────
if (MSVC)
    # Écrase les flags de Release injectés par CMake pour éviter les D9025
    string(REPLACE "/O2" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    string(REPLACE "/O2" "" CMAKE_C_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE}")
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE}")
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
    string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELWITHDEBINFO   "${CMAKE_C_FLAGS_RELWITHDEBINFO}")

    # Remove conflicting/aggressive flags — clean baseline
    add_compile_options(
            /MP             # Multi-processor compilation
            /W1             # Low warning level
            /O2             # Optimize for speed
            /Gy             # Function-level linking
            /Zc:threadSafeInit-
    )
    if(WHIP_BUILD_MODE STREQUAL "PROD_WITH_LOADER")
        add_compile_options(/GL)  # Whole Program Optimization (LTO) — prod only
    endif()
    add_compile_definitions(
            _CRT_SECURE_NO_WARNINGS
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            _WINDOWS
            _USRDLL
            _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR
            _USE_MATH_DEFINES
            NDEBUG
            INTERNALGHOSTCLIENT_EXPORTS
    )

endif ()

# ─── External Paths ───────────────────────────────────────────────────────────
set(WHIPNEXUS_DIR       "C:/Users/Java/Desktop/whip/WhipNexus")
set(WHIPNEXUS_LIB       "${WHIPNEXUS_DIR}/cmake-build-release/bin/Release/WhipNexus.lib")
set(WHIPSYSCALL_DIR     "C:/Users/Java/Desktop/whip/WhipSysCall")
set(WHIPSYSCALL_LIB     "${WHIPSYSCALL_DIR}/cmake-build-release/WhipSysCall.lib")
set(WHIPANTIDEBUG_DIR   "C:/Users/Java/CLionProjects/WhipAntiDebugger")
set(WHIPANTIDEBUG_LIB   "${WHIPANTIDEBUG_DIR}/cmake-build-release/WhipAntiDebugger.lib")
set(VMPROTECT_SDK_PATH  "C:/Users/Java/Desktop/VMP")

# ─── Imported Libraries ───────────────────────────────────────────────────────
add_library(WhipNexus STATIC IMPORTED)
set_target_properties(WhipNexus PROPERTIES
        IMPORTED_LOCATION "${WHIPNEXUS_LIB}"
        INTERFACE_LINK_LIBRARIES "${WHIPSYSCALL_LIB}"
)

add_library(WhipAntiDebug STATIC IMPORTED)
set_target_properties(WhipAntiDebug PROPERTIES
        IMPORTED_LOCATION "${WHIPANTIDEBUG_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${WHIPANTIDEBUG_DIR}"
)

# ─── Find Packages ────────────────────────────────────────────────────────────
find_package(Java REQUIRED)
find_package(JNI REQUIRED)
find_package(OpenGL REQUIRED)

if (NOT JNI_FOUND)
    message(FATAL_ERROR "JNI not found! Please install JDK and set JAVA_HOME.")
endif ()

message(STATUS "JNI include dirs: ${JNI_INCLUDE_DIRS}")

# ─── Directories ──────────────────────────────────────────────────────────────
set(SRC_DIR         ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(INCLUDES_DIR    ${CMAKE_CURRENT_SOURCE_DIR}/includes)
set(RESOURCES_DIR   ${CMAKE_CURRENT_SOURCE_DIR}/resources)
set(THIRDPARTY_DIR  ${SRC_DIR}/Thirdpary)
set(FREETYPE_DIR    ${THIRDPARTY_DIR}/freetype)
set(FRAMEWORK_DIR   ${THIRDPARTY_DIR}/framework)

# ─── ImGui ────────────────────────────────────────────────────────────────────
set(IMGUI_DIR "")
if (EXISTS "${THIRDPARTY_DIR}/Dear ImGui")
    set(IMGUI_DIR "${THIRDPARTY_DIR}/Dear ImGui")
elseif (EXISTS "${THIRDPARTY_DIR}/Dear_ImGui")
    set(IMGUI_DIR "${THIRDPARTY_DIR}/Dear_ImGui")
else ()
    message(WARNING "ImGui directory not found")
endif ()

# ─── Source Collection ────────────────────────────────────────────────────────
set(IMGUI_SOURCES "")
if (IMGUI_DIR)
    foreach(F
            imgui.cpp imgui_demo.cpp imgui_draw.cpp
            imgui_tables.cpp imgui_widgets.cpp imgui_freetype.cpp
    )
        if (EXISTS "${IMGUI_DIR}/${F}")
            list(APPEND IMGUI_SOURCES "${IMGUI_DIR}/${F}")
        endif ()
    endforeach()
    foreach(F
            backends/imgui_impl_opengl2.cpp
            backends/imgui_impl_win32.cpp
    )
        if (EXISTS "${IMGUI_DIR}/${F}")
            list(APPEND IMGUI_SOURCES "${IMGUI_DIR}/${F}")
        endif ()
    endforeach()
endif ()

set(FRAMEWORK_SOURCES "")
if (EXISTS "${FRAMEWORK_DIR}")
    file(GLOB FRAMEWORK_SOURCES
            ${FRAMEWORK_DIR}/helpers/*.cpp
            ${FRAMEWORK_DIR}/widgets/*.cpp
    )
endif ()

file(GLOB HOOK_SOURCES ${SRC_DIR}/gui/hook/*.c)

file(GLOB_RECURSE PROJECT_SOURCES "${SRC_DIR}/*.cpp" "${SRC_DIR}/*.c")
file(GLOB_RECURSE THIRDPARTY_FILES "${THIRDPARTY_DIR}/*.cpp" "${THIRDPARTY_DIR}/*.c")

# Remove third-party files from main sources
foreach(F ${IMGUI_SOURCES} ${FRAMEWORK_SOURCES} ${HOOK_SOURCES} ${THIRDPARTY_FILES})
    list(REMOVE_ITEM PROJECT_SOURCES ${F})
endforeach()


file(GLOB_RECURSE HEADERS "${INCLUDES_DIR}/*.h" "${INCLUDES_DIR}/*.hpp")

# ─── Target ───────────────────────────────────────────────────────────────────
add_library(${PROJECT_NAME} SHARED
        ${PROJECT_SOURCES}
        ${IMGUI_SOURCES}
        ${FRAMEWORK_SOURCES}
        ${HOOK_SOURCES}
        ${HEADERS}
        includes/util/nt.h
        src/event/MouseLeftClickEvent.cpp
        includes/event/sub/MouseLeftClickEvent.h
        includes/module/IGuiCustomRender.h
        includes/screen/IScreen.h
        includes/screen/ScreenType.h
        includes/screen/base/BaseScreen.h
        includes/screen/sub/ModuleScreen.h
        includes/util/ModuleUtils.h
        src/hud/sub/NotificationHUDElement.cpp
        includes/hud/sub/NotificationHUDElement.h
        src/module/impl/visual/TracerModule.cpp
        includes/module/impl/visual/TracerModule.h
        includes/auth/ErrorCode.h
        includes/auth/Credentials.h
        includes/auth/IAuthService.h
        includes/auth/session/Session.h
        includes/auth/session/SessionManager.h
        src/auth/session/SessionManager.cpp
        includes/auth/service/WhipAuthService.h
        src/auth/service/WhipAuthService.cpp
        includes/auth/config/IConfigService.h
        includes/auth/config/ConfigService.h
        includes/auth/version/VersionDetector.h
        src/auth/version/VersionDetector.cpp
        includes/event/sub/OnTickEvent.h
        src/event/OnTickEvent.cpp
        src/handler/ConfigManager.cpp
        includes/module/impl/config/PrivateConfigModule.h
        src/module/impl/config/PrivateConfigModule.cpp
        includes/event/sub/ModuleScreenDrawEvent.h
        src/event/ModuleScreenDrawEvent.cpp
        includes/event/sub/CanBeCollidedWithEvent.h
        src/event/CanBeCollidedWithEvent.cpp
        src/module/impl/visual/StorageEspModule.cpp
        includes/module/impl/visual/StorageEsp.h
        src/wrapper/minecraft/tileentity/TileEntity.cpp
        includes/wrapper/minecraft/tileentity/TileEntity.h
        src/wrapper/minecraft/client/gui/inventory/GuiContainer.cpp
        includes/wrapper/minecraft/client/gui/inventory/GuiContainer.h
        includes/wrapper/minecraft/world/chunk/Chunk.h
        includes/event/sub/EntityLivingUpdateEvent.h
        src/event/EntityLivingUpdateEvent.cpp
        includes/event/sub/StatusUpdateEvent.h
        src/event/StatusUpdateEvent.cpp
        src/module/impl/movement/noslow/NoSlowModule.cpp
        includes/module/impl/movement/noslow/NoSlowModule.h
        includes/module/impl/movement/noslow/mode/NoSlowMode.h
        includes/module/impl/movement/noslow/mode/NoItemReleaseMode.h
        src/module/impl/movement/noslow/mode/NoItemReleaseMode.cpp
        includes/module/impl/movement/noslow/mode/NoSlowMovementMode.h
        src/module/impl/movement/noslow/mode/NoSlowMovementMode.cpp
        includes/module/impl/movement/BridgeAssistModule.h
        src/module/impl/movement/BridgeAssistModule.cpp
        includes/module/impl/movement/QuickAccel.h
        src/module/impl/movement/QuickAccel.cpp
        includes/module/impl/movement/SnapTapModule.h
        src/module/impl/movement/SnapTapModule.cpp
        includes/module/impl/movement/Sprint.h
        src/module/impl/movement/Sprint.cpp
        includes/module/impl/movement/InvWalkModule.h
        src/module/impl/movement/InvWalkModule.cpp
        includes/module/impl/movement/NoJumpDelayModule.h
        src/module/impl/movement/NoJumpDelayModule.cpp
        includes/util/KawaseBlur.h
        src/util/KawaseBlur.cpp

        src/module/impl/setting/EnemiesModule.cpp
        includes/module/impl/setting/EnemiesModule.h
        includes/util/whipJson.h
        src/util/MojangAPIUtils.cpp
        includes/util/MojangAPIUtils.h
        includes/mutex/CustomMutex.h
        includes/util/algorithm/AESGCMAlgorithm.h
        src/util/algorithm/AESGCMAlgorithm.cpp
        includes/util/algorithm/AESEAlgorithm.h
        src/util/algorithm/AESEAlgorithm.cpp
        includes/util/algorithm/sha256.h
        src/util/algorithm/SHA256Algorithm.cpp
        includes/util/algorithm/p-256Algorithm.h
        src/util/algorithm/p-256Algorithm.cpp
        includes/util/algorithm/HKDFAlgorithm.h
        src/util/algorithm/HKDFAlgorithm.cpp
        includes/util/xor.h
        src/auth/ipc/LoaderIpcClient.cpp
        includes/auth/ipc/LoaderIpcClient.h
        includes/util/MinecraftVersionUtils.h
        includes/ClientMain.h
        src/ClientMain.cpp
        src/hook/classfile.cpp
        src/hook/dispatcher.cpp
        src/hook/instrumentation.cpp
        src/hook/uuid.cpp
        includes/hook/classfile.hpp
        includes/hook/embedded_transformer.hpp
        includes/hook/transformer_registry.hpp
        includes/hook/uuid.hpp
        src/hook/sub/RunTickHook.cpp
        includes/hook/sub/RunTickHook.h
        src/hook/sub/GetSlotAtPositionHook.cpp
        includes/hook/sub/GetSlotAtPositionHook.h
        includes/event/sub/dispatchKeypressesEvent.h
        src/event/DispatchKeypressesEvent.cpp
        includes/provider/impl/PacketProvider.h
        src/provider/impl/PacketProvider.cpp
        includes/provider/impl/GameStateProvider.h
        src/provider/impl/GameStateProvider.cpp
        includes/module/impl/network/backtrack/BacktrackModule.h
        src/module/impl/network/backtrack/BacktrackModule.cpp
        includes/module/impl/network/backtrack/BacktrackStructs.h
        includes/module/impl/network/backtrack/mode/IBacktrackMode.h
        includes/module/impl/network/backtrack/mode/LagMode.h
        src/module/impl/network/backtrack/mode/LagMode.cpp
        includes/module/impl/network/backtrack/mode/SmoothMode.h
        src/module/impl/network/backtrack/mode/SmoothMode.cpp
        includes/module/impl/network/backtrack/mode/AdvancedMode.h
        src/module/impl/network/backtrack/mode/AdvancedMode.cpp
        src/event/PlayerAttackEvent.cpp
        src/util/RenderUtils.cpp
        includes/util/RenderUtils.h
        src/util/RenderMatrixSnapshot.cpp
        includes/util/RenderMatrixSnapshot.h
        includes/wrapper/CVarsUpdater.h
        src/wrapper/CVarsUpdater.cpp
        includes/wrapper/minecraft/client/activerenderinfo/ActiveRenderInfo2.h
        includes/wrapper/minecraft/client/renderer/GlStateManager.h
        includes/wrapper/minecraft/network/play/server/S0CPacketSpawnPlayer.h
        src/wrapper/minecraft/network/play/server/S0CPacketSpawnPlayer.cpp
        includes/wrapper/minecraft/network/play/client/C05PacketPlayerLook.h
        src/wrapper/minecraft/network/play/client/C05PacketPlayerLook.cpp
        includes/hook/sub/KeyBindingIsPressed.h
        src/util/BlurShaders.cpp
        includes/util/BlurShaders.h
        src/util/GLStateManager.cpp
        includes/util/GLStateManager.h
        src/util/FramebufferManager.cpp
        includes/util/FramebufferManager.h
        src/util/BlurRenderer.cpp
        includes/util/BlurRenderer.h
        src/auth/security/CrtShim.cpp
        # Sentinel — modern WhipAntiDebugger integration (replaces the legacy
        # AntiDebugService that depended on the old WhipAntiDebug framework).
        includes/security/Sentinel.h
        src/security/Sentinel.cpp
        src/security/Sentinel_bridge.c
        includes/util/Inflate.h
        src/util/Inflate.cpp
        includes/module/impl/network/LagRangeModule.h
        src/module/impl/network/LagRangeModule.cpp
        includes/module/impl/misc/AutoToolModule.h
        src/module/impl/misc/AutoToolModule.cpp
        includes/module/impl/misc/ChestStealerModule.h
        src/module/impl/misc/ChestStealerModule.cpp
)


# ─── Include Directories ──────────────────────────────────────────────────────
target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${INCLUDES_DIR}
        ${SRC_DIR}
        ${JNI_INCLUDE_DIRS}
        ${WHIPNEXUS_DIR}/include
        ${WHIPSYSCALL_DIR}/include
        ${WHIPANTIDEBUG_DIR}
)

foreach(DIR
        "${IMGUI_DIR}"
        "${IMGUI_DIR}/backends"
        "${FRAMEWORK_DIR}/headers"
        "${FREETYPE_DIR}/include"
        "${THIRDPARTY_DIR}/OpenGL-master"
        "${THIRDPARTY_DIR}/glm"
        "${THIRDPARTY_DIR}/stb"
        "${INCLUDES_DIR}/gui/glfw"
        "${INCLUDES_DIR}/gui/hook"
        "${RESOURCES_DIR}/Font"
        "${RESOURCES_DIR}/Texture"
        "${DX_SDK_DIR}/Include"
)
    if (EXISTS "${DIR}")
        target_include_directories(${PROJECT_NAME} PRIVATE "${DIR}")
    endif ()
endforeach()

# ─── Link Directories ─────────────────────────────────────────────────────────
# Note: link_directories must be before add_library, or use target_link_directories
target_link_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/libs
        ${FREETYPE_DIR}/win64
)

# ─── Libraries ────────────────────────────────────────────────────────────────
set(BASE_LIBS
        kernel32 user32 gdi32 winspool comdlg32 advapi32
        shell32 ole32 oleaut32 uuid odbc32 odbccp32
        opengl32 ntdll winhttp
        bcrypt crypt32 psapi iphlpapi shlwapi winmm imagehlp
)

set(OPTIONAL_LIBS "")
# glew32 : lié seulement si le .lib est présent dans libs/
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libs/glew32.lib")
    list(APPEND OPTIONAL_LIBS glew32)
else ()
    message(STATUS "glew32.lib absent de libs/ — non lié (OpenGL2 backend ne le requiert pas)")
endif ()
# glfw3 : lié seulement si présent
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libs/glfw3.lib")
    list(APPEND OPTIONAL_LIBS glfw3)
endif ()
if (EXISTS "${FREETYPE_DIR}/win64/freetype.lib")
    list(APPEND OPTIONAL_LIBS freetype)
endif ()

# ─── VMProtect ────────────────────────────────────────────────────────────────
set(VMPROTECT_LIB "${CMAKE_BINARY_DIR}/bin/VMProtectSDK64.lib")
set(VMPROTECT_DLL "${VMPROTECT_SDK_PATH}/VMProtectSDK64.dll")

if (BUILD_WITH_VMPROTECT AND EXISTS "${VMPROTECT_LIB}")
    list(APPEND OPTIONAL_LIBS "${VMPROTECT_LIB}")
    target_compile_definitions(${PROJECT_NAME} PRIVATE VMP)
    target_include_directories(${PROJECT_NAME} PRIVATE "${VMPROTECT_SDK_PATH}")
    message(STATUS "VMProtect enabled")

    if (EXISTS "${VMPROTECT_DLL}")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${VMPROTECT_DLL}"
                $<TARGET_FILE_DIR:${PROJECT_NAME}>
        )
    endif ()
else ()
    message(STATUS "VMProtect disabled or not found")
endif ()

# ─── Link Libraries ───────────────────────────────────────────────────────────
target_link_libraries(${PROJECT_NAME} PRIVATE
        ${BASE_LIBS}
        ${OPTIONAL_LIBS}
        ${JNI_LIBRARIES}
        WhipNexus
        WhipAntiDebug
)

# ─── Target Properties ────────────────────────────────────────────────────────
set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY    ${CMAKE_BINARY_DIR}/bin
        LIBRARY_OUTPUT_DIRECTORY    ${CMAKE_BINARY_DIR}/lib
        ARCHIVE_OUTPUT_DIRECTORY    ${CMAKE_BINARY_DIR}/lib
        PREFIX                      ""
        SUFFIX                      ".dll"
        PDB_OUTPUT_DIRECTORY        ${CMAKE_BINARY_DIR}/bin
        PDB_NAME                    ${PROJECT_NAME}
)

# ─── MSVC Linker Options (safe, preserves .rdata) ─────────────────────────────
if (MSVC)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
            ALGORITHM_HEADER_INCLUDED=1
    )

    if (IMGUI_SOURCES)
        target_compile_definitions(${PROJECT_NAME} PRIVATE IMGUI_IMPL_OPENGL_LOADER_GLEW)
    endif ()

    target_compile_options(${PROJECT_NAME} PRIVATE
            /std:c++20
            /MT         # Static runtime
            /Zi         # Generate PDB debug info
            # CFG disabled: WhipClient is manually-mapped by WhipMmap, which
            # does NOT patch __guard_check_icall_fptr / __guard_dispatch_icall_fptr
            # at 0x664950/0x664960. With CFG instrumented (Guard Flags=0x100),
            # the first indirect call jumps through the unpatched slot to the
            # raw RVA of _guard_check_icall_nop (~0x72156a), which lands on
            # non-executable memory in the host process → DEP NX fault →
            # AV in ntdll!KiUserExceptionDispatch → WER dump.
            /guard:cf-
    )

    target_link_options(${PROJECT_NAME} PRIVATE
            /SUBSYSTEM:WINDOWS
            /DEBUG:FULL         # Emit full PDB
            /OPT:REF            # Remove unreferenced code/data
            /OPT:ICF            # Identical code folding
            /DYNAMICBASE        # ASLR
    )
    if(WHIP_BUILD_MODE STREQUAL "PROD_WITH_LOADER")
        target_link_options(${PROJECT_NAME} PRIVATE /LTCG)  # Pairs with /GL — prod only
    endif()
endif ()

# ─── Copy Runtime DLLs ────────────────────────────────────────────────────────
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libs")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/libs"
            $<TARGET_FILE_DIR:${PROJECT_NAME}>
    )
endif ()

# ─── Install ──────────────────────────────────────────────────────────────────
install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)
install(FILES ${CMAKE_BINARY_DIR}/bin/${PROJECT_NAME}.pdb
        DESTINATION bin OPTIONAL
)

# ─── Custom Target: Build & Inject ────────────────────────────────────────────
# inject       → build WhipClient THEN inject (full pipeline)
# inject_only  → inject directly, skip build check (use when nothing changed)
add_custom_target(inject
    COMMAND cmd.exe /c "${CMAKE_SOURCE_DIR}/inject.bat"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building WhipClient and injecting into Lunar Client..."
    DEPENDS ${PROJECT_NAME}
    VERBATIM
)

add_custom_target(inject_only
    COMMAND cmd.exe /c "${CMAKE_SOURCE_DIR}/inject.bat"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Injecting WhipClient (no build step)..."
    VERBATIM
)
