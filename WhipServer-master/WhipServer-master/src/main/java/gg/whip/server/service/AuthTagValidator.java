package gg.whip.server.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Phase 1 auth_tag validator.
 * <p>
 * The loader baked a per-download {@code authSalt[16]} in its overlay. At each
 * of the 3 anti-debug call sites it computes
 * {@code tag = HMAC-SHA256(authSalt, buf || score_le32)[:8]} and embeds the
 * 64-bit tag in the corresponding packet (INIT_REQUEST, FILE_REQUEST, IPC
 * LOADER_CONFIG). The server recomputes from {@code download.authSalt} (with
 * score=0 for clean) and rejects any mismatch — closes the NOPable
 * {@code Sentinel::taint} bypass documented in AUTH_THREAT_MODEL.md §5.
 */
@Service
public class AuthTagValidator {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AuthTagValidator.class);

    public enum MismatchCause {
        /** authTag matches — no mismatch. */
        NONE,
        /** Phase 3 fingerprint wrong: tag matches when fingerprint is zeroed out. */
        FINGERPRINT,
        /** Sentinel score != 0: tag matches neither with nor without fingerprint. */
        SCORE_OR_UNKNOWN
    }

    /** Compute the 64-bit auth tag for a clean (score=0) buffer. */
    public long compute(byte[] authSalt, byte[] algoSeed, byte[] codeFingerprint, byte[] buf) {
        return computeWithScore(authSalt, algoSeed, codeFingerprint, buf, 0);
    }

    public long compute(byte[] authSalt, byte[] algoSeed, byte[] codeFingerprint, String s) {
        return compute(authSalt, algoSeed, codeFingerprint, s.getBytes(StandardCharsets.UTF_8));
    }

    /** Constant-time comparison of expected vs received tag. */
    public boolean validate(byte[] authSalt, byte[] algoSeed, byte[] codeFingerprint, byte[] buf, long receivedTag) {
        long expected = compute(authSalt, algoSeed, codeFingerprint, buf);
        return constantTimeEquals(expected, receivedTag);
    }

    public boolean validate(byte[] authSalt, byte[] algoSeed, byte[] codeFingerprint, String s, long receivedTag) {
        return validate(authSalt, algoSeed, codeFingerprint, s.getBytes(StandardCharsets.UTF_8), receivedTag);
    }

    /**
     * Validate and return a human-readable diagnosis of the mismatch cause.
     * Tries progressively simpler computations to isolate which Phase failed.
     */
    public MismatchCause diagnose(byte[] authSalt, byte[] algoSeed, byte[] codeFingerprint,
                                  byte[] buf, long receivedTag) {
        // Full validation (Phase 1+2+3, score=0)
        if (constantTimeEquals(compute(authSalt, algoSeed, codeFingerprint, buf), receivedTag)) {
            return MismatchCause.NONE;
        }

        // Try without fingerprint (Phase 1+2 only, zeros for codeFingerprint)
        // If this matches → the stored expectedFingerprint doesn't match the
        // runtime .text hash (ASLR delta, wrong loader binary, or VMP transform).
        byte[] zeros = new byte[32];
        if (constantTimeEquals(compute(authSalt, algoSeed, zeros, buf), receivedTag)) {
            log.warn("AUTH_TAG DIAG: mismatch caused by FINGERPRINT — " +
                    "tag matches when fingerprint=zeros. Stored fp={}",
                    toHex(codeFingerprint));
            return MismatchCause.FINGERPRINT;
        }

        // Neither match → score != 0 or the auth data itself is wrong.
        log.warn("AUTH_TAG DIAG: mismatch NOT caused by fingerprint alone — " +
                "likely Sentinel score != 0 or corrupted authSalt/algoSeed. " +
                "Stored fp={}", toHex(codeFingerprint));
        return MismatchCause.SCORE_OR_UNKNOWN;
    }

    private long computeWithScore(byte[] authSalt, byte[] algoSeed, byte[] codeFingerprint, byte[] buf, int score) {
        try {
            // Phase 2+3: keyMaterial = SHA-256(authSalt || algoSeed || codeFingerprint).
            //   - algoSeed: per-download → reverse loader A doesn't help with B
            //   - codeFingerprint: SHA-256 of .text → any byte patched breaks HMAC
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(authSalt);
            sha.update(algoSeed);
            sha.update(codeFingerprint);
            byte[] keyMaterial = sha.digest();

            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(keyMaterial, "HmacSHA256"));
            hmac.update(buf);
            byte[] scoreBytes = new byte[]{
                    (byte) (score & 0xFF),
                    (byte) ((score >>> 8) & 0xFF),
                    (byte) ((score >>> 16) & 0xFF),
                    (byte) ((score >>> 24) & 0xFF),
            };
            hmac.update(scoreBytes);
            byte[] mac = hmac.doFinal();
            long tag = 0;
            for (int i = 0; i < 8; i++) {
                tag |= ((long) (mac[i] & 0xFF)) << (i * 8);
            }
            return tag;
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    private static String toHex(byte[] b) {
        if (b == null) return "null";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02X", v & 0xFF));
        return sb.toString();
    }

    private static boolean constantTimeEquals(long a, long b) {
        // Reuse MessageDigest.isEqual on the byte representation for timing safety.
        byte[] aBytes = new byte[8];
        byte[] bBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            aBytes[i] = (byte) ((a >>> (i * 8)) & 0xFF);
            bBytes[i] = (byte) ((b >>> (i * 8)) & 0xFF);
        }
        return MessageDigest.isEqual(aBytes, bBytes);
    }
}
