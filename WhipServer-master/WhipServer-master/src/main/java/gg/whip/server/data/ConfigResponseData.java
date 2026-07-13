package gg.whip.server.data;

import java.util.List;

/**
 * Data for CONFIG_RESPONSE packet (0x51)
 */
public record ConfigResponseData(
    boolean success,
    byte operation,
    String message,
    byte[] configData,           // for LOAD response
    List<ConfigEntry> entries    // for LIST response
) {
    public record ConfigEntry(
        String id,
        String name,
        String description,
        String author,
        String createdDate,
        String modifiedDate
    ) {}

    public static ConfigResponseData success(byte operation, String message) {
        return new ConfigResponseData(true, operation, message, null, null);
    }

    public static ConfigResponseData successWithData(byte operation, byte[] data) {
        return new ConfigResponseData(true, operation, null, data, null);
    }

    public static ConfigResponseData successWithEntries(byte operation, List<ConfigEntry> entries) {
        return new ConfigResponseData(true, operation, null, null, entries);
    }

    public static ConfigResponseData error(byte operation, String message) {
        return new ConfigResponseData(false, operation, message, null, null);
    }
}
