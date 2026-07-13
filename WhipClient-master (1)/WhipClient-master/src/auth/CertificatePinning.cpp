#include "auth/CertificatePinning.h"
#include "auth/session/Session.h"
#include "security/Sentinel.h"
#include "util/HashUtils.h"
#include "util/ClientStrings.h"
#include "util/Debug.h"
#include <whipnexus/SyscallManager.h>
#include <whipsyscall/WhipSysCall.h>
#include "antidebug/vm/vm_cpp.hpp"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

static SyscallResolver& GetSyscallResolver() {
    static SyscallResolver s_resolver;
    static bool s_init = s_resolver.Init();
    (void)s_init;
    return s_resolver;
}

#pragma optimize("", off)
#pragma strict_gs_check(on)

bool CertificatePinning::validateCertificateFingerprint(const byte* certDerData, u32 certDerLength) {
#ifdef VMP
    VMProtectBeginUltra("CertificatePinning_validateCertificateFingerprint");
#endif

    Sentinel::recheck();
    Sentinel::verify();

    if (!certDerData || certDerLength == 0) {
        terminateOnFailure("Invalid certificate data");
    }

    byte hash[32];
    computeCertificateSha256(certDerData, certDerLength, hash);

    char computedFingerprint[65];
    hashToHex(hash, computedFingerprint);

    const char* expectedFingerprint = Strings::authServerPubkeyFingerprint();

    {
        auto cascade = ad::vm::ScoreCascade::from_key(vm_runtime_key_stable());
        uint64_t encodedDiff = compareFingerprints(computedFingerprint, expectedFingerprint);
        if (cascade.decode(encodedDiff) != 0u) {
            terminateOnFailure("Certificate fingerprint mismatch");
        }
    }

#ifdef VMP
    VMProtectEnd();
#endif

    return true;
}

bool CertificatePinning::validateFingerprintHex(const char* fingerprintHex) {
#ifdef VMP
    VMProtectBeginUltra("CertificatePinning_validateFingerprintHex");
#endif

    Sentinel::recheck();
    Sentinel::verify();

    if (!fingerprintHex) {
        terminateOnFailure("Null fingerprint");
    }

    const char* expectedFingerprint = Strings::authServerPubkeyFingerprint();

    {
        auto cascade = ad::vm::ScoreCascade::from_key(vm_runtime_key_stable());
        uint64_t encodedDiff = compareFingerprints(fingerprintHex, expectedFingerprint);
        if (cascade.decode(encodedDiff) != 0u) {
            terminateOnFailure("Fingerprint mismatch");
        }
    }

#ifdef VMP
    VMProtectEnd();
#endif

    return true;
}

void CertificatePinning::computeCertificateSha256(const byte* certData, u32 certLength, byte* outHash32) {
#ifdef VMP
    VMProtectBeginUltra("CertificatePinning_computeCertificateSha256");
#endif

    picosha2::hash256(certData, certData + certLength, outHash32, outHash32 + 32);

#ifdef VMP
    VMProtectEnd();
#endif
}

void CertificatePinning::hashToHex(const byte* hash32, char* hexOut65) {
#ifdef VMP
    VMProtectBeginUltra("CertificatePinning_hashToHex");
#endif

    picosha2::bytes_to_hex_string(hash32, hash32 + 32, hexOut65, 65);

#ifdef VMP
    VMProtectEnd();
#endif
}

uint64_t CertificatePinning::compareFingerprints(const char* fp1, const char* fp2) {
#ifdef VMP
    VMProtectBeginUltra("CertificatePinning_compareFingerprints");
#endif

    auto cascade = ad::vm::ScoreCascade::from_key(vm_runtime_key_stable());

    if (!fp1 || !fp2) {

        return cascade.encode(0xFFu);
    }

    volatile byte result = 0;
    for (u32 i = 0; i < 64; ++i) {
        volatile byte c1 = (byte)fp1[i];
        volatile byte c2 = (byte)fp2[i];
        result |= (c1 ^ c2);
    }

    volatile byte t1 = (byte)fp1[64];
    volatile byte t2 = (byte)fp2[64];
    result |= (t1 ^ t2);

    uint64_t encoded = cascade.encode(static_cast<uint32_t>(result));

#ifdef VMP
    VMProtectEnd();
#endif

    return encoded;
}

[[noreturn]] void CertificatePinning::terminateOnFailure(const char* reason) {
#ifdef VMP
    VMProtectBeginUltra("CertificatePinning_terminateOnFailure");
#endif

    WORD ssn; PVOID addr;
    if (GetSyscallResolver().ResolveByName("NtTerminateProcess", ssn, addr)) {
        SyscallInvoker::Invoke(ssn, GetCurrentProcess(), (PVOID)(ULONG_PTR)0xDEAD);
    }

    for (;;) {
        if (GetSyscallResolver().ResolveByName("NtTerminateProcess", ssn, addr)) {
            SyscallInvoker::Invoke(ssn, GetCurrentProcess(), (PVOID)(ULONG_PTR)0xDEAD);
        }
    }
#ifdef VMP
    VMProtectEnd();
#endif
}

#pragma optimize("", on)
