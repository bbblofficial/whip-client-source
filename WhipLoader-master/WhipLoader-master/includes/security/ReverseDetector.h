#pragma once

#include <cstdint>
#include <vector>

// ReverseDetector — background monitor for RE/analysis tools.
//
// On detection:
//   1. Captures screenshots of all physical monitors.
//   2. Kills detected RE tools.
//   3. Sends REVERSE_DETECTED packet (with screenshots) to the server.
//   4. TerminateProcess the game (javaw.exe) by PID if injected.
//   5. TerminateProcess the loader.

class WhipNexusClient;

namespace ReverseDetector {
    // Enable SeDebugPrivilege + deny PROCESS_TERMINATE/SUSPEND/VM_WRITE to
    // our process DACL. Also called internally by start().
    void protect();

    // Start the background detection thread.
    // gamePid : PID of the injected game process (javaw.exe).
    //           On detection the game is killed before the loader dies.
    //           Pass 0 when not yet injected.
    void start(WhipNexusClient* client, void* heartbeatThread,
               const char* pcName = "", const char* executablePath = "",
               uint32_t gamePid = 0);

    void stop();

    // Synchronous one-shot check — call at key steps (download, inject…).
    // gamePid : same semantics as start(). Pass the game PID when available.
    void checkAndKill(WhipNexusClient* client, const char* tag,
                      uint32_t gamePid = 0);

    // Kill known RE tools (x64dbg by name, module signature, or cert).
    // No screenshots, no network — safe to call pre-auth and pre-connect.
    void killDebugTools();

    // Passive detection scan — returns true if x64dbg or VMP-bypass tooling is
    // found via any of: process name, x64bridge/ScyllaHide modules in any process,
    // Authenticode cert (Duncan Ogilvie), hardware breakpoints on our threads, or
    // ScyllaHide DLL injected into our own process.
    // Does NOT kill, take screenshots, or send packets — safe to call anywhere.
    bool isX64dbgDetected();

    // Capture each physical monitor as a separate JPEG (50% scale, WIC-encoded).
    std::vector<std::vector<uint8_t>> captureScreen();
}
