#pragma optimize("", off)
#include "whipnexus/X509CertBuilder.h"
#include "whipnexus/SyscallManager.h"

#ifdef BUILD_WITH_VMPROTECT
#include "VMProtectSDK.h"
#endif

// ── DER encoding helpers ────────────────────────────────────────────────────

u32 X509CertBuilder::derWriteLength(byte* buf, u32 len) {
    VMProtectBeginUltra("X509CertBuilder_derWriteLength");
    if (len < 128) {
        buf[0] = (byte)len;
        return 1;
    } else if (len < 256) {
        buf[0] = 0x81;
        buf[1] = (byte)len;
        return 2;
    } else {
        buf[0] = 0x82;
        buf[1] = (byte)(len >> 8);
        buf[2] = (byte)(len);
        return 3;
    }
    VMProtectEnd();
}

u32 X509CertBuilder::derWriteTag(byte* buf, byte tag, u32 contentLen) {
    VMProtectBeginUltra("X509CertBuilder_derWriteTag");
    buf[0] = tag;
    return 1 + derWriteLength(buf + 1, contentLen);
    VMProtectEnd();
}

u32 X509CertBuilder::derWriteSequence(byte* buf, const byte* content, u32 contentLen) {
    VMProtectBeginUltra("X509CertBuilder_derWriteSequence");
    u32 pos = derWriteTag(buf, 0x30, contentLen);
    SyscallManager::SecureMemCpy(buf + pos, content, contentLen);
    return pos + contentLen;
    VMProtectEnd();
}

u32 X509CertBuilder::derWriteInteger(byte* buf, const byte* val, u32 valLen) {
    VMProtectBeginUltra("X509CertBuilder_derWriteInteger");
    // DER INTEGER: skip leading zeros but keep at least 1 byte.
    // Prepend 0x00 if high bit is set (positive integer).
    u32 skip = 0;
    while (skip < valLen - 1 && val[skip] == 0 && (val[skip + 1] & 0x80) == 0) {
        skip++;
    }

    bool needPad = (val[skip] & 0x80) != 0;
    u32 intLen = (valLen - skip) + (needPad ? 1 : 0);

    u32 pos = 0;
    buf[pos++] = 0x02; // INTEGER tag
    pos += derWriteLength(buf + pos, intLen);

    if (needPad) {
        buf[pos++] = 0x00;
    }
    SyscallManager::SecureMemCpy(buf + pos, val + skip, valLen - skip);
    pos += valLen - skip;
    return pos;
    VMProtectEnd();
}

u32 X509CertBuilder::derWriteOid(byte* buf, const byte* oid, u32 oidLen) {
    VMProtectBeginUltra("X509CertBuilder_derWriteOid");
    buf[0] = 0x06; // OID tag
    u32 pos = 1 + derWriteLength(buf + 1, oidLen);
    SyscallManager::SecureMemCpy(buf + pos, oid, oidLen);
    return pos + oidLen;
    VMProtectEnd();
}

u32 X509CertBuilder::derWriteUtf8String(byte* buf, const char* str, u32 strLen) {
    VMProtectBeginUltra("X509CertBuilder_derWriteUtf8String");
    buf[0] = 0x0C; // UTF8String tag
    u32 pos = 1 + derWriteLength(buf + 1, strLen);
    SyscallManager::SecureMemCpy(buf + pos, str, strLen);
    return pos + strLen;
    VMProtectEnd();
}

u32 X509CertBuilder::derWriteUtcTime(byte* buf, const char* time13) {
    VMProtectBeginUltra("X509CertBuilder_derWriteUtcTime");
    buf[0] = 0x17; // UTCTime tag
    u32 pos = 1 + derWriteLength(buf + 1, 13);
    SyscallManager::SecureMemCpy(buf + pos, time13, 13);
    return pos + 13;
    VMProtectEnd();
}

u32 X509CertBuilder::derWriteExplicitTag(byte* buf, byte tagNum, const byte* content, u32 contentLen) {
    VMProtectBeginUltra("X509CertBuilder_derWriteExplicitTag");
    buf[0] = 0xA0 | tagNum; // Context-specific, constructed
    u32 pos = 1 + derWriteLength(buf + 1, contentLen);
    SyscallManager::SecureMemCpy(buf + pos, content, contentLen);
    return pos + contentLen;
    VMProtectEnd();
}

u32 X509CertBuilder::derWriteBitString(byte* buf, const byte* data, u32 dataLen) {
    VMProtectBeginUltra("X509CertBuilder_derWriteBitString");
    // BIT STRING: 1 byte for unused bits count (0) + data
    u32 totalLen = 1 + dataLen;
    buf[0] = 0x03; // BIT STRING tag
    u32 pos = 1 + derWriteLength(buf + 1, totalLen);
    buf[pos++] = 0x00; // 0 unused bits
    SyscallManager::SecureMemCpy(buf + pos, data, dataLen);
    return pos + dataLen;
    VMProtectEnd();
}

// ── Raw ECDSA to DER conversion ────────────────────────────────────────────

bool X509CertBuilder::rawEcdsaToDer(const byte* rawSig, u32 rawSigLen,
                                     byte* derOut, u32* derOutLen) {
    VMProtectBeginUltra("X509CertBuilder_rawEcdsaToDer");
    if (rawSigLen != 64) return false;

    const byte* r = rawSig;
    const byte* s = rawSig + 32;

    // Encode r and s as DER INTEGERs into temp buffers
    byte rDer[36]; // max: tag(1) + len(1) + pad(1) + 32 = 35
    byte sDer[36];
    u32 rDerLen = derWriteInteger(rDer, r, 32);
    u32 sDerLen = derWriteInteger(sDer, s, 32);

    // Wrap in SEQUENCE
    u32 seqContentLen = rDerLen + sDerLen;
    u32 pos = derWriteTag(derOut, 0x30, seqContentLen);
    SyscallManager::SecureMemCpy(derOut + pos, rDer, rDerLen);
    pos += rDerLen;
    SyscallManager::SecureMemCpy(derOut + pos, sDer, sDerLen);
    pos += sDerLen;

    *derOutLen = pos;
    return true;
    VMProtectEnd();
}

// ── Build self-signed certificate ──────────────────────────────────────────

bool X509CertBuilder::buildSelfSignedCert(
    CryptoService* crypto,
    const byte* ecdsaPubX509, u32 ecdsaPubX509Len,
    void* ecdsaPrivKey,
    byte* certOut, u32* certOutLen) {
    VMProtectBeginUltra("X509CertBuilder_buildSelfSignedCert");

    // OID: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
    static const byte OID_ECDSA_SHA256[] = {
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02
    };
    // OID: commonName (2.5.4.3)
    static const byte OID_COMMON_NAME[] = { 0x55, 0x04, 0x03 };

    // Subject/Issuer: CN=WhipNexus
    static const char CN_VALUE[] = "WhipNexus";
    static const u32 CN_LEN = 9;

    // Validity: 250101000000Z to 350101000000Z (2025 to 2035)
    static const char NOT_BEFORE[] = "250101000000Z";
    static const char NOT_AFTER[]  = "350101000000Z";

    // Scratch buffer for building TBSCertificate
    byte tbs[1024];
    u32 tbsPos = 0;

    // ── 1. version [0] EXPLICIT INTEGER v3 (2) ──
    {
        byte versionInt[3];
        versionInt[0] = 0x02; // INTEGER tag
        versionInt[1] = 0x01; // length 1
        versionInt[2] = 0x02; // value 2 (v3)
        tbsPos += derWriteExplicitTag(tbs + tbsPos, 0, versionInt, 3);
    }

    // ── 2. serialNumber INTEGER (random 20 bytes) ──
    {
        byte serial[20];
        crypto->generateRandomBytes(serial, 20);
        serial[0] &= 0x7F; // Ensure positive
        if (serial[0] == 0) serial[0] = 0x01; // Non-zero first byte
        tbsPos += derWriteInteger(tbs + tbsPos, serial, 20);
    }

    // ── 3. signature AlgorithmIdentifier (ecdsa-with-SHA256) ──
    {
        byte algIdContent[32];
        u32 algIdLen = derWriteOid(algIdContent, OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256));
        tbsPos += derWriteSequence(tbs + tbsPos, algIdContent, algIdLen);
    }

    // ── 4. issuer Name (CN=WhipNexus) ──
    {
        // AttributeValue: UTF8String
        byte attrValue[32];
        u32 attrValueLen = derWriteUtf8String(attrValue, CN_VALUE, CN_LEN);

        // AttributeType: OID commonName
        byte attrType[8];
        u32 attrTypeLen = derWriteOid(attrType, OID_COMMON_NAME, sizeof(OID_COMMON_NAME));

        // SEQUENCE { type, value }
        byte attrSeqContent[64];
        SyscallManager::SecureMemCpy(attrSeqContent, attrType, attrTypeLen);
        SyscallManager::SecureMemCpy(attrSeqContent + attrTypeLen, attrValue, attrValueLen);
        byte attrSeq[64];
        u32 attrSeqLen = derWriteSequence(attrSeq, attrSeqContent, attrTypeLen + attrValueLen);

        // SET { SEQUENCE }
        byte setContent[64];
        u32 setPos = derWriteTag(setContent, 0x31, attrSeqLen);
        SyscallManager::SecureMemCpy(setContent + setPos, attrSeq, attrSeqLen);
        setPos += attrSeqLen;

        // Name SEQUENCE { SET }
        tbsPos += derWriteSequence(tbs + tbsPos, setContent, setPos);
    }

    // ── 5. validity Validity { notBefore, notAfter } ──
    {
        byte validityContent[64];
        u32 vPos = 0;
        vPos += derWriteUtcTime(validityContent + vPos, NOT_BEFORE);
        vPos += derWriteUtcTime(validityContent + vPos, NOT_AFTER);
        tbsPos += derWriteSequence(tbs + tbsPos, validityContent, vPos);
    }

    // ── 6. subject Name (same as issuer: CN=WhipNexus) ──
    {
        // Same structure as issuer
        byte attrValue[32];
        u32 attrValueLen = derWriteUtf8String(attrValue, CN_VALUE, CN_LEN);
        byte attrType[8];
        u32 attrTypeLen = derWriteOid(attrType, OID_COMMON_NAME, sizeof(OID_COMMON_NAME));
        byte attrSeqContent[64];
        SyscallManager::SecureMemCpy(attrSeqContent, attrType, attrTypeLen);
        SyscallManager::SecureMemCpy(attrSeqContent + attrTypeLen, attrValue, attrValueLen);
        byte attrSeq[64];
        u32 attrSeqLen = derWriteSequence(attrSeq, attrSeqContent, attrTypeLen + attrValueLen);
        byte setContent[64];
        u32 setPos = derWriteTag(setContent, 0x31, attrSeqLen);
        SyscallManager::SecureMemCpy(setContent + setPos, attrSeq, attrSeqLen);
        setPos += attrSeqLen;
        tbsPos += derWriteSequence(tbs + tbsPos, setContent, setPos);
    }

    // ── 7. subjectPublicKeyInfo (the 91-byte X.509 blob from generateEcdsaKeyPair) ──
    {
        SyscallManager::SecureMemCpy(tbs + tbsPos, ecdsaPubX509, ecdsaPubX509Len);
        tbsPos += ecdsaPubX509Len;
    }

    // ── Wrap TBSCertificate in SEQUENCE ──
    byte tbsSequence[1024];
    u32 tbsSeqLen = derWriteSequence(tbsSequence, tbs, tbsPos);

    // ── Sign the TBSCertificate ──
    byte rawSig[256];
    u32 rawSigLen = 0;
    if (!crypto->signEcdsa(ecdsaPrivKey, tbsSequence, tbsSeqLen, rawSig, &rawSigLen)) {
        return false;
    }

    // Convert raw r||s to DER-encoded signature
    byte derSig[128];
    u32 derSigLen = 0;
    if (!rawEcdsaToDer(rawSig, rawSigLen, derSig, &derSigLen)) {
        return false;
    }

    // ── Build outer Certificate SEQUENCE ──
    byte certContent[1024];
    u32 certContentPos = 0;

    // 1. TBSCertificate
    SyscallManager::SecureMemCpy(certContent + certContentPos, tbsSequence, tbsSeqLen);
    certContentPos += tbsSeqLen;

    // 2. signatureAlgorithm (ecdsa-with-SHA256)
    {
        byte algIdContent[32];
        u32 algIdLen = derWriteOid(algIdContent, OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256));
        certContentPos += derWriteSequence(certContent + certContentPos, algIdContent, algIdLen);
    }

    // 3. signatureValue BIT STRING
    certContentPos += derWriteBitString(certContent + certContentPos, derSig, derSigLen);

    // Wrap in outer SEQUENCE
    u32 totalLen = derWriteSequence(certOut, certContent, certContentPos);
    *certOutLen = totalLen;

    return true;
    VMProtectEnd();
}
#pragma optimize("", on)