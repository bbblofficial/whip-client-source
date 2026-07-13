package gg.whip.server.data;

public record FileChunkMetaData(
    String fileKey,
    int totalSize,
    int compressedSize,
    int chunkCount,
    int chunkSize,
    boolean compressed,
    long timestamp
) {
    public static FileChunkMetaData create(String fileKey, int totalSize, int compressedSize,
                                          int chunkCount, int chunkSize, boolean compressed) {
        return new FileChunkMetaData(
            fileKey,
            totalSize,
            compressedSize,
            chunkCount,
            chunkSize,
            compressed,
            System.currentTimeMillis() / 1000
        );
    }
}
