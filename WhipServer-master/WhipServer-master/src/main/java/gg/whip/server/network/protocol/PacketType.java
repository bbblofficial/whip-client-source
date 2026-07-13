package gg.whip.server.network.protocol;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Getter
@RequiredArgsConstructor
public enum PacketType {

    CLIENT_HELLO(0x01),
    SERVER_HELLO(0x02),
    INIT_REQUEST(0x12),
    INIT_RESPONSE(0x13),
    PRODUCT_SELECT(0x14),
    AUTH_RESPONSE(0x15),
    CLIENT_AUTH(0x16),
    CLIENT_AUTH_RESPONSE(0x17),
    MACHINE_INFO(0x18),
    MACHINE_INFO_RESPONSE(0x19),
    FILE_REQUEST(0x20),
    FILE_RESPONSE(0x21),
    KEYED_FILE_REQUEST(0x22),
    KEYED_FILE_RESPONSE(0x23),
    FILE_CHUNK_META(0x24),
    FILE_CHUNK(0x25),
    HEARTBEAT(0x30),
    HEARTBEAT_ACK(0x31),
    DISCONNECT(0x40),
    SESSION_REVOKED(0x41),
    /** Client → Server: live setting mutation. Body:
     *    keyLen(2) + key + valueType(1) + valueData(N) + clientNonce(8)
     *  See WhipLoader/REMOTE_CONFIG_DESIGN.md. */
    SETTING_MUTATE_REQUEST(0x44),
    /** Server → Client: signed mutation result. Body:
     *    keyLen(2) + key + status(1) + sequence(8) + expiresAt(8) +
     *    valueType(1) + valueData(N) + ed25519Sig(64) + clientNonce(8) */
    SETTING_MUTATE_RESPONSE(0x45),
    CONFIG_REQUEST(0x80),
    CONFIG_RESPONSE(0x81),
    REVERSE_DETECTED(0x90),
    /** Loader → Server : screenshots liés à un REVERSE_DETECTED (même requestId).
     *  Body : requestId(string) + count(u32) + [len(u32) + bytes(jpeg)]* */
    REVERSE_DETECTED_SCREENSHOTS(0x93),
    /** Client → Server : connexion bloquée par le serveur.
     *  Body : parentProcess(string) + screenshotCount(u32) + [len(u32)+bytes]* */
    CONNECT_FAIL_REPORT(0x92),
    /** Server → Client (DLL): "crash your host now". DLL deliberately
     *  AVs to take down the game process. Triggered from /admin/sessions
     *  via pg_notify('whip_sync', '{"entity":"session","action":"crash"...}').
     *  See WhipLoader/DUMP_THREAT_MODEL.md and admin sessions UI. */
    SESSION_CRASH(0x91),
    ERROR(0xFF);

    private final int id;

    private static final Map<Integer, PacketType> BY_ID = new HashMap<>();

    static {
        for (PacketType type : values()) {
            BY_ID.put(type.id, type);
        }
    }

    public static PacketType fromId(int id) {
        return BY_ID.get(id);
    }
}