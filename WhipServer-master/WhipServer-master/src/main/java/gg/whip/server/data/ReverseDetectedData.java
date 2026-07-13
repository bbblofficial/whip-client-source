package gg.whip.server.data;

import java.util.List;

/**
 * Data for REVERSE_DETECTED packet (0x90).
 * Format: sessionToken(32) + score(u32) + checksRun(u32) + checksHit(u32) + checkMask(u32)
 *       + flags(u32) + report(string) + pcName(string) + executablePath(string)
 *       + timestamp(8) + requestId(string) + authHmac(32)
 *       + screenshotCount(u32) + [screenshotLen(u32) + screenshotBytes(N)]* per monitor
 */
public record ReverseDetectedData(
    byte[] sessionToken,
    long score,
    long checksRun,
    long checksHit,
    long checkMask,
    long flags,
    String report,
    String pcName,
    String executablePath,
    long timestamp,
    String requestId,
    byte[] authHmac,
    List<byte[]> screenshots  // one JPEG per physical monitor; empty list if absent/old client
) {
}
