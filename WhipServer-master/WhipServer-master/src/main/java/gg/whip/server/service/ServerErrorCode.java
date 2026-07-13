package gg.whip.server.service;

/**
 * Server error codes sent to clients.
 * Clients receive only the numeric code.
 * Staff documentation for error codes.
 */
public enum ServerErrorCode {
    // General errors (1-9)
    INVALID_STATE(1, "Invalid session state"),
    INVALID_TIMESTAMP(2, "Timestamp validation failed"),
    INVALID_REQUEST(3, "Malformed request data"),
    RATE_LIMIT_EXCEEDED(4, "Too many requests"),
    SERVER_ERROR(5, "Internal server error"),

    // Authentication errors (10-19)
    INVALID_CREDENTIALS(10, "Invalid download ID or HWID"),
    REVOKED_DOWNLOAD(11, "Download ID has been revoked"),
    NO_VALID_LICENSE(12, "No active license found"),
    ACCOUNT_BLACKLISTED(13, "User account is blacklisted"),
    INSUFFICIENT_PERMISSIONS(14, "Operation requires higher privileges"),
    HWID_MISMATCH(15, "HWID does not match registered machines"),

    // Session errors (20-29)
    SESSION_EXPIRED(20, "Session has expired"),
    SESSION_NOT_FOUND(21, "Session not found"),
    INVALID_TOKEN(22, "Invalid authentication token"),
    SESSION_ALREADY_EXISTS(23, "Active session already exists"),

    // Product/License errors (30-39)
    PRODUCT_NOT_FOUND(30, "Requested product not found"),
    LICENSE_EXPIRED(31, "License has expired"),
    LICENSE_SUSPENDED(32, "License is suspended"),
    LICENSE_REVOKED(33, "License has been revoked"),

    // Download errors (40-49)
    FILE_NOT_FOUND(40, "Requested file not found"),
    DOWNLOAD_FAILED(41, "File download failed"),
    INVALID_FILE_REQUEST(42, "Invalid file request"),
    DOWNLOADS_DISABLED(43, "Downloads temporarily disabled"),

    // Config errors (50-59)
    CONFIG_NOT_FOUND(50, "Configuration not found"),
    CONFIG_ACCESS_DENIED(51, "Access denied to configuration"),

    // Machine errors (60-69)
    MACHINE_NOT_REGISTERED(60, "Machine not registered"),
    MACHINE_REVOKED(61, "Machine has been revoked"),
    MAX_MACHINES_REACHED(62, "Maximum machines limit reached"),

    // Security errors (70-79)
    NONCE_REPLAY_DETECTED(70, "Replay attack detected"),
    SUSPICIOUS_ACTIVITY(71, "Suspicious activity detected"),
    BLACKLIST_VIOLATION(72, "Blacklist violation"),
    ANOMALY_DETECTED(73, "Anomaly detected in request pattern");

    private final int code;
    private final String internalDescription;

    ServerErrorCode(int code, String internalDescription) {
        this.code = code;
        this.internalDescription = internalDescription;
    }

    public int getCode() {
        return code;
    }

    public String getInternalDescription() {
        return internalDescription;
    }
}
