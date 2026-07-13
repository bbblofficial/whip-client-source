package gg.whip.server.data;

/**
 * Data for CONFIG_REQUEST packet (0x80)
 * Format: operation(1) + timestamp(8) + [op-specific fields] + authHmac(32)
 * Operations: CREATE(0), LOAD(1), DELETE(2), MODIFY(3), LIST(4)
 * No sessionToken (session identified by channel) — no requestId (anti-replay via packet nonce + timestamp)
 */
public record ConfigRequestData(
    byte operation,          // 0=CREATE, 1=LOAD, 2=DELETE, 3=MODIFY, 4=LIST
    long timestamp,
    String configId,
    String configName,
    String description,
    String author,
    byte[] configData,       // nullable — only for CREATE/MODIFY
    String pcName,           // PC name for audit
    String executablePath,   // Executable path for audit
    byte[] authHmac          // HMAC-SHA256(userSecret, packetType || timestamp)
) {
    public static final byte OP_CREATE = 0;
    public static final byte OP_LOAD   = 1;
    public static final byte OP_DELETE = 2;
    public static final byte OP_MODIFY = 3;
    public static final byte OP_LIST   = 4;
}
