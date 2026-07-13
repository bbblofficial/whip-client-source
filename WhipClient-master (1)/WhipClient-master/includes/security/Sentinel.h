#pragma once

#include <cstdint>

namespace Sentinel {

    void init();

    void cleanup();

    void taint(uint8_t* data, uint32_t length);

    void recheck();

    void verify();

    uint64_t snapshot();

    bool consumeReport(char* reportText, uint32_t reportCap,
                       uint32_t* score, uint32_t* checksRun,
                       uint32_t* checksHit, uint32_t* checkMask,
                       uint32_t* flags);

    bool pollInstantAttach(uint32_t* outReason);
}
