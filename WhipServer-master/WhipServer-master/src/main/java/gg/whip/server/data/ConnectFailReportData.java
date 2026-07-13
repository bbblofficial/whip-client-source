package gg.whip.server.data;

import java.util.List;

public record ConnectFailReportData(
        String parentProcess,
        List<byte[]> screenshots,
        String downloadId,
        String hwid,
        String detectionTag
) {}
