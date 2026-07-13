package gg.whip.server.handler.impl;

import gg.whip.server.data.ClientSession;
import gg.whip.server.data.RawPacket;
import gg.whip.server.data.SettingTokenBucket;
import gg.whip.server.handler.IPacketHandler;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketType;
import gg.whip.server.network.protocol.PacketWriter;
import gg.whip.server.service.SettingSigningService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * Handles SETTING_MUTATE_REQUEST (0x44).
 *
 * Stateless from a DB perspective: no SQL, no audit table, no persistence.
 * All state (sequence counter, token buckets) lives on ClientSession and
 * dies when the connection closes. The server is a pure transformation
 * oracle — receive (key, value), check auth + rate limit, sign with
 * Ed25519, return.
 *
 * Wire formats: see PacketType.java javadoc + REMOTE_CONFIG_DESIGN.md.
 */
@Component
@RequiredArgsConstructor
public class SettingMutateHandler implements IPacketHandler {

    private static final Logger log = LoggerFactory.getLogger(SettingMutateHandler.class);

    private static final byte SCHEMA_VERSION_V1 = 1;

    // Status codes — must mirror SettingMutateStatus on the client side.
    private static final byte STATUS_OK                = 0;
    private static final byte STATUS_RATE_LIMITED      = 1;
    private static final byte STATUS_PERMISSION_DENIED = 2;
    private static final byte STATUS_INVALID_VALUE     = 3;
    private static final byte STATUS_UNKNOWN_SETTING   = 4;
    private static final byte STATUS_SESSION_EXPIRED   = 5;
    private static final byte STATUS_INTERNAL_ERROR    = 6;

    // Default TTL on a signed mutation: 24h. Past this the client treats
    // the setting as expired and reverts to its default value, forcing a
    // new RPC if the user wants to keep it.
    private static final long DEFAULT_TTL_MS = 24L * 3600L * 1000L;

    // Hard cap on settingKey + valueData so a malformed packet can't OOM.
    private static final int MAX_KEY_LEN   = 256;
    private static final int MAX_VALUE_LEN = 64;

    private final PacketSender packetSender;
    private final PacketWriter packetWriter;
    private final SettingSigningService signingService;

    @Override
    public void handle(ClientSession session, RawPacket packet) {
        if (!session.isAuthenticated()) {
            log.debug("[SETTING_MUTATE] unauthenticated session {} — drop",
                    session.getRemoteAddress());
            return;
        }

        ByteBuffer buf = ByteBuffer.wrap(packet.payload()).order(ByteOrder.BIG_ENDIAN);

        // --- parse request ----------------------------------------------
        String settingKey;
        byte   valueType;
        byte[] valueData;
        long   clientNonce;
        try {
            int keyLen = Short.toUnsignedInt(buf.getShort());
            if (keyLen <= 0 || keyLen > MAX_KEY_LEN) {
                respondError(session, "", STATUS_INVALID_VALUE, 0L);
                return;
            }
            byte[] keyBytes = new byte[keyLen];
            buf.get(keyBytes);
            settingKey = new String(keyBytes, StandardCharsets.UTF_8);

            valueType = buf.get();
            int valueLen = wireValueLen(valueType);
            if (valueLen < 0 || valueLen > MAX_VALUE_LEN || buf.remaining() < valueLen + 8) {
                respondError(session, settingKey, STATUS_INVALID_VALUE, 0L);
                return;
            }
            valueData = new byte[valueLen];
            buf.get(valueData);

            clientNonce = buf.getLong();
        } catch (Exception e) {
            log.debug("[SETTING_MUTATE] malformed packet from {}: {}",
                    session.getRemoteAddress(), e.getMessage());
            return;
        }

        // --- token bucket ----------------------------------------------
        SettingTokenBucket bucket = session.getSettingTokenBuckets()
                .computeIfAbsent(settingKey, k -> new SettingTokenBucket());
        if (!bucket.tryConsume()) {
            long retryAfter = bucket.retryAfterMs();
            log.debug("[SETTING_MUTATE] rate-limited user={} key={} retryAfter={}ms",
                    safeUser(session), settingKey, retryAfter);
            respondError(session, settingKey, STATUS_RATE_LIMITED,
                    System.currentTimeMillis() + retryAfter);
            return;
        }

        // TODO Phase 2: permission check based on user tier / setting policy.
        // For now any authenticated user can mutate any setting.

        // --- sign + respond --------------------------------------------
        long sequence  = session.getSettingSequenceCounter().incrementAndGet();
        long expiresAt = System.currentTimeMillis() + DEFAULT_TTL_MS;

        byte[] sessionToken = session.getSessionToken();
        if (sessionToken == null || sessionToken.length != 32) {
            log.warn("[SETTING_MUTATE] session has no 32-byte sessionToken — auth broken?");
            respondError(session, settingKey, STATUS_INTERNAL_ERROR, 0L);
            return;
        }
        String hwid = session.getHwid() != null ? session.getHwid() : "";

        byte[] payload = buildCanonicalPayload(SettingSigningService.PUBKEY_VERSION,
                settingKey, sessionToken, hwid, sequence, expiresAt,
                valueType, valueData);
        byte[] sig = signingService.sign(payload);

        // --- response wire ---------------------------------------------
        byte[] keyBytes = settingKey.getBytes(StandardCharsets.UTF_8);
        ByteBuffer out = ByteBuffer.allocate(2 + keyBytes.length + 1 + 8 + 8 + 1
                + valueData.length + sig.length + 8)
                .order(ByteOrder.BIG_ENDIAN);
        out.putShort((short) keyBytes.length);
        out.put(keyBytes);
        out.put(STATUS_OK);
        out.putLong(sequence);
        out.putLong(expiresAt);
        out.put(valueType);
        out.put(valueData);
        out.put(sig);
        out.putLong(clientNonce);

        packetSender.sendEncrypted(session, PacketType.SETTING_MUTATE_RESPONSE, out.array());

        if (log.isDebugEnabled()) {
            log.debug("[SETTING_MUTATE] OK user={} key={} seq={} type={} valueLen={}",
                    safeUser(session), settingKey, sequence, valueType, valueData.length);
        }
    }

    private void respondError(ClientSession session, String key, byte status, long expiresAtOrRetryUntil) {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        // Empty value + zero sig — client drops anyway because status != OK.
        ByteBuffer out = ByteBuffer.allocate(2 + keyBytes.length + 1 + 8 + 8 + 1
                + 0 + SettingSigningService.SIG_LEN + 8)
                .order(ByteOrder.BIG_ENDIAN);
        out.putShort((short) keyBytes.length);
        out.put(keyBytes);
        out.put(status);
        out.putLong(0L);                    // sequence — not used on error path
        out.putLong(expiresAtOrRetryUntil); // doubles as retry-after for RATE_LIMITED
        out.put((byte) 0);                  // valueType = Bool placeholder
        // no value data
        out.put(new byte[SettingSigningService.SIG_LEN]); // zero sig
        out.putLong(0L);                    // clientNonce — error path is one-shot
        packetSender.sendEncrypted(session, PacketType.SETTING_MUTATE_RESPONSE, out.array());
    }

    /**
     * Canonical payload that gets signed. MUST byte-match what
     * SignedSettingPayload::build produces on the client, or the verify
     * fails. See WhipClient/includes/auth/setting/SignedSettingPayload.h
     * for the binary contract.
     */
    static byte[] buildCanonicalPayload(byte pubkeyVersion,
                                         String settingKey,
                                         byte[] sessionToken,
                                         String hwid,
                                         long sequence,
                                         long expiresAt,
                                         byte valueType,
                                         byte[] valueData) {
        byte[] keyBytes  = settingKey.getBytes(StandardCharsets.UTF_8);
        byte[] hwidBytes = hwid.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(64 + keyBytes.length + hwidBytes.length + valueData.length);
        out.write(SCHEMA_VERSION_V1);
        out.write(pubkeyVersion);
        out.write((keyBytes.length >>> 8) & 0xFF);
        out.write(keyBytes.length & 0xFF);
        out.writeBytes(keyBytes);
        out.writeBytes(sessionToken);  // 32 bytes
        out.write((hwidBytes.length >>> 8) & 0xFF);
        out.write(hwidBytes.length & 0xFF);
        out.writeBytes(hwidBytes);
        writeBE64(out, sequence);
        writeBE64(out, expiresAt);
        out.write(valueType & 0xFF);
        out.writeBytes(valueData);
        return out.toByteArray();
    }

    private static void writeBE64(ByteArrayOutputStream out, long v) {
        for (int i = 7; i >= 0; --i) out.write((int) ((v >>> (8 * i)) & 0xFF));
    }

    /** Map valueType byte to the implied length on the wire. -1 if unknown. */
    private static int wireValueLen(byte valueType) {
        return switch (valueType) {
            case 0 -> 1;             // Bool
            case 1, 2, 3 -> 4;       // Int32, Float32, UInt32
            case 4 -> 4;             // Color (RGBA)
            case 6, 7 -> 8;          // IntRange, FloatRange
            case 8, 9 -> 4;          // Keybind, Combo
            // Variable-length types (String=5, MultiCombo=10) need length-
            // prefixed wire — not yet supported in Phase 1.
            default -> -1;
        };
    }

    private static String safeUser(ClientSession session) {
        return session.getUser() != null ? session.getUser().getUsername() : "?";
    }
}
