#ifndef WHIPNEXUS_X509CERTBUILDER_H
#define WHIPNEXUS_X509CERTBUILDER_H

#include "Types.h"
#include "CryptoService.h"

// Minimal self-signed X.509 v3 DER certificate builder.
// Uses BCrypt only (no crypt32 dependency). Supports ECDSA P-256.
class X509CertBuilder {
public:
    // Build a self-signed X.509 v3 DER certificate from an ECDSA P-256 key pair.
    // ecdsaPubX509: 91-byte X.509 SubjectPublicKeyInfo (from generateEcdsaKeyPair)
    // ecdsaPrivKey: ECDSA private key handle (for signing the TBSCertificate)
    // certOut: output buffer (must be at least 512 bytes)
    // certOutLen: receives actual cert length
    static bool buildSelfSignedCert(
        CryptoService* crypto,
        const byte* ecdsaPubX509, u32 ecdsaPubX509Len,
        void* ecdsaPrivKey,
        byte* certOut, u32* certOutLen);

    // Convert BCrypt raw ECDSA signature (r||s, 64 bytes) to DER-encoded
    // SEQUENCE { INTEGER r, INTEGER s } as required by TLS and X.509.
    static bool rawEcdsaToDer(const byte* rawSig, u32 rawSigLen,
                              byte* derOut, u32* derOutLen);

private:
    // DER encoding helpers
    static u32 derWriteLength(byte* buf, u32 len);
    static u32 derWriteTag(byte* buf, byte tag, u32 contentLen);
    static u32 derWriteInteger(byte* buf, const byte* val, u32 valLen);
    static u32 derWriteOid(byte* buf, const byte* oid, u32 oidLen);
    static u32 derWriteUtf8String(byte* buf, const char* str, u32 strLen);
    static u32 derWriteUtcTime(byte* buf, const char* time13);
    static u32 derWriteExplicitTag(byte* buf, byte tagNum, const byte* content, u32 contentLen);
    static u32 derWriteBitString(byte* buf, const byte* data, u32 dataLen);
    static u32 derWriteSequence(byte* buf, const byte* content, u32 contentLen);
};

#endif // WHIPNEXUS_X509CERTBUILDER_H