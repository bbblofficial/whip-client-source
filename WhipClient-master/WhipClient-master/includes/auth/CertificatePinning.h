#pragma once
#include <cstdint>
#include <windows.h>
#include <whipnexus/Types.h>

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#pragma optimize("", off)

class CertificatePinning {
public:

    static bool validateCertificateFingerprint(const byte* certDerData, u32 certDerLength);

    static bool validateFingerprintHex(const char* fingerprintHex);

private:

    static void computeCertificateSha256(const byte* certData, u32 certLength, byte* outHash32);

    static void hashToHex(const byte* hash32, char* hexOut65);

    static uint64_t compareFingerprints(const char* fp1, const char* fp2);

    [[noreturn]] static void terminateOnFailure(const char* reason);
};

#pragma optimize("", on)
