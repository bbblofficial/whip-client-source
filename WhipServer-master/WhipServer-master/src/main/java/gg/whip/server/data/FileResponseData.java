package gg.whip.server.data;

public record FileResponseData(
    boolean success,
    boolean compressed,
    byte[] encryptedData,
    int originalSize,
    int compressedSize,
    String errorMessage
) {
    /**
     * Uncompressed payload. {@code originalSize} is the plaintext byte
     * length (pre-encryption), {@code compressed} is false.
     */
    public static FileResponseData success(byte[] encryptedData, int originalSize) {
        return new FileResponseData(true, false, encryptedData, originalSize, originalSize, null);
    }

    /**
     * DEFLATE-compressed payload. {@code originalSize} is the *uncompressed*
     * plaintext length, {@code compressedSize} is the deflated blob length
     * (and equals {@code encryptedData.length - 12 - 16} after stripping
     * the GCM nonce/tag the receiver will peel off).
     */
    public static FileResponseData successCompressed(byte[] encryptedData,
                                                     int originalSize, int compressedSize) {
        return new FileResponseData(true, true, encryptedData, originalSize, compressedSize, null);
    }

    public static FileResponseData error(String message) {
        return new FileResponseData(false, false, null, 0, 0, message);
    }
}
