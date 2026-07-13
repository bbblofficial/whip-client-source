package gg.whip.server.data;

/**
 * Data for KEYED_FILE_REQUEST packet (0x22)
 * Format: sessionToken(32) + string(key) + timestamp(8) + requestId(string) + authHmac(32)
 * Client specifies which file it wants via key.
 */
public record KeyedFileRequestData(
    byte[] sessionToken,  // 32 bytes
    String key,           // File key (e.g. "versions", "mappings")
    long timestamp,       // Epoch seconds
    String requestId,     // UUID hex string for anti-replay
    String pcName,        // PC name for audit
    String executablePath, // Executable path for audit
    byte[] authHmac       // HMAC-SHA256 auth token
) {
}
