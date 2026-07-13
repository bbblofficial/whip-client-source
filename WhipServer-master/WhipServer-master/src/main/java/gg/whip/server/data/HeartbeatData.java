package gg.whip.server.data;

public record HeartbeatData(
        byte[] sessionToken,
        long timestamp,
        byte[] challengeResponse,
        String requestId,
        String pcName,
        String executablePath
) {}