package gg.whip.server.data;

public record FileChunkData(
    String fileKey,
    int chunkIndex,
    byte[] chunkData,
    long timestamp
) {
    public static FileChunkData create(String fileKey, int chunkIndex, byte[] chunkData) {
        return new FileChunkData(
            fileKey,
            chunkIndex,
            chunkData,
            System.currentTimeMillis() / 1000
        );
    }
}
