package gg.whip.server.data;

public record InitRequestData(
        boolean useHwid,
        String identifier,
        String hwid,
        String pcName,
        String os,
        String executablePath,
        long timestamp,
        long authTag,
        String gpuName,
        String cpuBrand,
        String ramHex,
        String boardModel,
        String screenInfo,
        String storageInfo
) {}
