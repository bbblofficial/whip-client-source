package gg.whip.server.data;

/**
 * Data for FILE_REQUEST packet (0x20)
 * Format: sessionToken(32) + key(string) + timestamp(8) + requestId(string) + authHmac(32)
 * File key is sent by client but resolved server-side via session download sequence (zero trust).
 */
public record FileRequestData(
    byte[] sessionToken,  // 32 bytes - Session token for authentication
    String key,           // File key from client (ignored in zero-trust mode, server uses nextFileKey())
    long timestamp,       // Epoch seconds - Request timestamp
    String requestId,     // UUID hex string for anti-replay
    String pcName,        // PC name for audit
    String executablePath, // Executable path for audit
    byte[] authHmac,      // HMAC-SHA256 auth token
    long authTag          // Phase 1 auth_tag = HMAC(authSalt, pcName||score)[:8]
) {
}
