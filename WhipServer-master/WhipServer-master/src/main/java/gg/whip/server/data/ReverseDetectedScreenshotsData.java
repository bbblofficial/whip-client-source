package gg.whip.server.data;

import java.util.List;

/**
 * Data for REVERSE_DETECTED_SCREENSHOTS packet (0x93).
 * Sent immediately after REVERSE_DETECTED (0x90) on the same connection.
 * Format: requestId(string) + count(u32) + [len(u32) + bytes(jpeg)]*
 */
public record ReverseDetectedScreenshotsData(
    String requestId,
    List<byte[]> screenshots
) {
}
