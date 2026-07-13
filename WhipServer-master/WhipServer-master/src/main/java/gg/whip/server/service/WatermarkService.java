package gg.whip.server.service;

import gg.whip.server.model.DllWatermark;
import fr.whip.api.model.User;
import gg.whip.server.config.ServerProperties;
import gg.whip.server.repository.DllWatermarkRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Per-download watermark patcher.
 *
 * <p>WhipClient.dll embeds a 32-byte slot in .rdata starting with the
 * 8-byte ASCII magic {@code "WHP_WM01"}. Before encrypting the DLL
 * for transport, we locate the magic, overwrite the trailing 24 bytes
 * with a unique payload, and persist the {@code (sessionUuid → user)}
 * mapping so leaked dumps can be attributed back to the source.
 *
 * <p>Payload layout (32 bytes total, replacing the placeholder in place):
 * <pre>
 *   [0..7]   magic         "WHP_WM01"   (kept as-is)
 *   [8..23]  sessionUuid   16 random bytes (stored in DB as canonical UUID)
 *   [24..31] hmacTrunc     HMAC-SHA256(secret, sessionUuid || userId || hwid)[:8]
 * </pre>
 *
 * See {@code DUMP_THREAT_MODEL.md §5.3}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WatermarkService {

    /**
     * 8-byte sentinel identifying the placeholder slot in WhipClient.dll.
     * Non-printable on purpose: an attacker running `strings` on a dump
     * sees nothing obvious. Must stay byte-identical to g_whipWatermark[]
     * in WhipClient/src/DllMain.cpp and the corresponding MAGIC in
     * WhipServer ScanLeakTool + WhipSite scan-leak action.
     */
    public static final byte[] MAGIC = new byte[]{
        (byte)0xC7, (byte)0xA3, (byte)0x91, (byte)0x4E,
        (byte)0xF8, (byte)0x52, (byte)0xB6, (byte)0xD0
    };

    public static final int SLOT_SIZE = 32;
    public static final int UUID_BYTES_OFFSET = 8;
    public static final int UUID_BYTES_LEN = 16;
    public static final int HMAC_OFFSET = 24;
    public static final int HMAC_TRUNC_LEN = 8;

    private final DllWatermarkRepository repository;
    private final ServerProperties serverProperties;
    private final java.security.SecureRandom rng = new java.security.SecureRandom();

    /**
     * Locate the watermark slot in {@code dllBytes}, write a fresh per-
     * download payload in place, and persist the mapping. Returns the
     * sessionUuid that was embedded — useful for logging.
     *
     * <p>If the magic isn't found (e.g., serving a non-WhipClient module),
     * returns {@code null} and leaves the bytes untouched.
     */
    @Transactional
    public String patchAndPersist(byte[] dllBytes, User user, String hwid,
                                  String ip, String pcName, UUID downloadId) {
        int slotOff = findMagic(dllBytes);
        if (slotOff < 0) {
            return null;
        }

        // Generate a fresh 128-bit session id, write it as-is into the slot.
        byte[] uuidBytes = new byte[UUID_BYTES_LEN];
        rng.nextBytes(uuidBytes);
        UUID sessionUuid = bytesToUuid(uuidBytes);

        // HMAC binds the session id to user identity so an attacker can't
        // splice another user's leaked uuid into their own dump.
        byte[] hmacBytes = hmac(uuidBytes,
                user != null ? user.getId().toString() : "",
                hwid != null ? hwid : "");

        System.arraycopy(uuidBytes, 0, dllBytes, slotOff + UUID_BYTES_OFFSET, UUID_BYTES_LEN);
        System.arraycopy(hmacBytes, 0, dllBytes, slotOff + HMAC_OFFSET, HMAC_TRUNC_LEN);

        DllWatermark wm = new DllWatermark(
                sessionUuid.toString(),
                user != null ? user.getId() : null,
                user != null ? user.getDiscordId() : null,
                hwid,
                ip,
                pcName,
                bytesToHex(hmacBytes),
                downloadId);
        repository.save(wm);

        log.info("Watermark embedded: session={} user={} ip={} slotOff=0x{}",
                sessionUuid, user != null ? user.getUsername() : "?",
                ip, Integer.toHexString(slotOff));
        return sessionUuid.toString();
    }

    /** Find the magic prefix in the DLL bytes. Naive scan — small DLL, fast. */
    public int findMagic(byte[] bytes) {
        outer:
        for (int i = 0; i + SLOT_SIZE <= bytes.length; i++) {
            for (int j = 0; j < MAGIC.length; j++) {
                if (bytes[i + j] != MAGIC[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    /** Look up a watermark from a leaked dump's session uuid bytes. */
    public java.util.Optional<DllWatermark> lookupBySessionUuid(String sessionUuid) {
        return repository.findBySessionUuid(sessionUuid);
    }

    private byte[] hmac(byte[] uuidBytes, String userId, String hwid) {
        try {
            String secret = serverProperties.getWatermark().getSecret();
            byte[] key = (secret == null || secret.isEmpty())
                    ? new byte[32]
                    : secret.getBytes(StandardCharsets.UTF_8);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(uuidBytes);
            mac.update(userId.getBytes(StandardCharsets.UTF_8));
            mac.update(hwid.getBytes(StandardCharsets.UTF_8));
            byte[] full = mac.doFinal();
            byte[] trunc = new byte[HMAC_TRUNC_LEN];
            System.arraycopy(full, 0, trunc, 0, HMAC_TRUNC_LEN);
            return trunc;
        } catch (Exception e) {
            throw new RuntimeException("HMAC failed", e);
        }
    }

    private static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return new UUID(bb.getLong(), bb.getLong());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
