package gg.whip.server.data;

public record ProductSelectData(
        String productCode,
        String pcName,
        String executablePath,
        long timestamp
) {}
