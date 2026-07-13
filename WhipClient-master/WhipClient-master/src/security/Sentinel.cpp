#pragma optimize("", off)
#include "security/Sentinel.h"

#ifdef VMP
#include "VMProtectSDK.h"
#define VMP_BEGIN_ULTRA(x) VMProtectBeginUltra(x)
#define VMP_END()          VMProtectEnd()
#else
#define VMP_BEGIN_ULTRA(x) ((void)0)
#define VMP_END()          ((void)0)
#endif

extern "C" {
    void sentinel_bridge_init(void);
    void sentinel_bridge_cleanup(void);
    void sentinel_bridge_taint(unsigned char* data, unsigned int length);
    void sentinel_bridge_recheck(void);
    void sentinel_bridge_verify(void);
    unsigned long long sentinel_bridge_snapshot(void);
    int sentinel_bridge_consume_report(char* outText, unsigned int outCap,
                                       unsigned int* score, unsigned int* checksRun,
                                       unsigned int* checksHit, unsigned int* checkMask,
                                       unsigned int* flags);
    int sentinel_bridge_attach_poll(unsigned int* outReason);
}

namespace Sentinel {

void init() {
    VMP_BEGIN_ULTRA("Sentinel_init");
    sentinel_bridge_init();
    VMP_END();
}

void cleanup() {
    VMP_BEGIN_ULTRA("Sentinel_cleanup");
    sentinel_bridge_cleanup();
    VMP_END();
}

void taint(uint8_t* data, uint32_t length) {
    VMP_BEGIN_ULTRA("Sentinel_taint");
    sentinel_bridge_taint(reinterpret_cast<unsigned char*>(data),
                          static_cast<unsigned int>(length));
    VMP_END();
}

void recheck() {
    VMP_BEGIN_ULTRA("Sentinel_recheck");
    sentinel_bridge_recheck();
    VMP_END();
}

void verify() {
    VMP_BEGIN_ULTRA("Sentinel_verify");
    sentinel_bridge_verify();
    VMP_END();
}

uint64_t snapshot() {
    return static_cast<uint64_t>(sentinel_bridge_snapshot());
}

bool consumeReport(char* reportText, uint32_t reportCap,
                   uint32_t* score, uint32_t* checksRun,
                   uint32_t* checksHit, uint32_t* checkMask,
                   uint32_t* flags) {
    VMP_BEGIN_ULTRA("Sentinel_consumeReport");
    int got = sentinel_bridge_consume_report(reportText, static_cast<unsigned int>(reportCap),
                                             reinterpret_cast<unsigned int*>(score),
                                             reinterpret_cast<unsigned int*>(checksRun),
                                             reinterpret_cast<unsigned int*>(checksHit),
                                             reinterpret_cast<unsigned int*>(checkMask),
                                             reinterpret_cast<unsigned int*>(flags));
    VMP_END();
    return got != 0;
}

bool pollInstantAttach(uint32_t* outReason) {
    VMP_BEGIN_ULTRA("Sentinel_pollInstantAttach");
    unsigned int reason = 0u;
    int got = sentinel_bridge_attach_poll(&reason);
    if (outReason) *outReason = static_cast<uint32_t>(reason);
    VMP_END();
    return got != 0;
}

}

#pragma optimize("", on)
