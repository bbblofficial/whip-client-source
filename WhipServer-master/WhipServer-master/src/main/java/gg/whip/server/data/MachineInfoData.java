package gg.whip.server.data;

/**
 * Data for MACHINE_INFO packet (0x18)
 * Format: sessionToken(32) + string(mcUsername) + string(pcName) + timestamp(8) + requestId(string) + authHmac(32)
 */
public record MachineInfoData(
    byte[] sessionToken,  // 32 bytes
    String mcUsername,     // Minecraft username
    String pcName,        // PC name
    long timestamp,       // Epoch seconds
    String requestId,     // UUID hex string for anti-replay
    byte[] authHmac       // HMAC-SHA256 auth token
) {
}
