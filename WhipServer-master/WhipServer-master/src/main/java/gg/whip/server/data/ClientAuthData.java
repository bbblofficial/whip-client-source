package gg.whip.server.data;

public record ClientAuthData(
        byte[] temporaryClientToken,
        byte[] clientAttestationToken,
        String hwid,
        String pcName,
        String executablePath,
        long timestamp,
        long loaderAuthTag
) {}
