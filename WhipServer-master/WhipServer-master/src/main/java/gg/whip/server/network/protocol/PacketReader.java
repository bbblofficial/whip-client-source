package gg.whip.server.network.protocol;

import gg.whip.server.data.ClientAuthData;
import gg.whip.server.data.ClientHelloData;
import gg.whip.server.data.ConfigRequestData;
import gg.whip.server.data.FileRequestData;
import gg.whip.server.data.HeartbeatData;
import gg.whip.server.data.InitRequestData;
import gg.whip.server.data.KeyedFileRequestData;
import gg.whip.server.data.MachineInfoData;
import gg.whip.server.data.ProductSelectData;
import gg.whip.server.data.ConnectFailReportData;
import gg.whip.server.data.ReverseDetectedData;
import gg.whip.server.data.ReverseDetectedScreenshotsData;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class PacketReader {

    public ClientHelloData readClientHello(byte[] payload) {
        return BinaryReader.read(payload, r -> new ClientHelloData(
                r.readInt(),
                r.readFixedBytes(32),
                r.readBytes()
        ));
    }

    public HeartbeatData readHeartbeat(byte[] payload) {
        return BinaryReader.read(payload, r -> new HeartbeatData(
                r.readFixedBytes(32),
                r.readLong(),
                r.readFixedBytes(32),
                r.readString(),
                r.readString(),
                r.readString()
        ));
    }

    public InitRequestData readInitRequest(byte[] payload) {
        return BinaryReader.read(payload, r -> {
            boolean useHwid = r.readBoolean();
            String identifier = r.readString();
            String hwid = r.readString();
            String pcName = r.readString();
            String os = r.readString();
            String executablePath = r.readString();
            long timestamp = r.readLong();
            long authTag = r.hasRemaining() ? r.readLong() : 0;
            String gpuName    = r.hasRemaining() ? r.readString() : "";
            String cpuBrand   = r.hasRemaining() ? r.readString() : "";
            String ramHex     = r.hasRemaining() ? r.readString() : "";
            String boardModel = r.hasRemaining() ? r.readString() : "";
            String screenInfo = r.hasRemaining() ? r.readString() : "";
            String storageInfo = r.hasRemaining() ? r.readString() : "";
            return new InitRequestData(useHwid, identifier, hwid, pcName, os,
                    executablePath, timestamp, authTag, gpuName, cpuBrand, ramHex,
                    boardModel, screenInfo, storageInfo);
        });
    }

    public ProductSelectData readProductSelect(byte[] payload) {
        return BinaryReader.read(payload, r -> new ProductSelectData(
                r.readString(),
                r.readString(),
                r.readString(),
                r.readLong()
        ));
    }

    public ClientAuthData readClientAuth(byte[] payload) {
        return BinaryReader.read(payload, r -> new ClientAuthData(
                r.readFixedBytes(32),
                r.readFixedBytes(32),
                r.readString(),
                r.readString(),
                r.readString(),
                r.readLong(),
                r.readLong()
        ));
    }

    public FileRequestData readFileRequest(byte[] payload) {
        return BinaryReader.read(payload, r -> {
            byte[] sessionToken = r.readFixedBytes(32);
            String key = r.readString();
            long timestamp = r.readLong();
            String requestId = r.readString();
            String pcName = r.readString();
            String executablePath = r.readString();
            byte[] authHmac = r.readFixedBytes(32);
            long authTag = r.readLong();
            return new FileRequestData(sessionToken, key, timestamp, requestId, pcName, executablePath, authHmac, authTag);
        });
    }

    public KeyedFileRequestData readKeyedFileRequest(byte[] payload) {
        return BinaryReader.read(payload, r -> {
            byte[] sessionToken = r.readFixedBytes(32);
            String key = r.readString();
            long timestamp = r.readLong();
            String requestId = r.readString();
            String pcName = r.readString();
            String executablePath = r.readString();
            byte[] authHmac = r.readFixedBytes(32);
            return new KeyedFileRequestData(sessionToken, key, timestamp, requestId, pcName, executablePath, authHmac);
        });
    }

    public MachineInfoData readMachineInfo(byte[] payload) {
        return BinaryReader.read(payload, r -> {
            byte[] sessionToken = r.readFixedBytes(32);
            String mcUsername = r.readString();
            String pcName = r.readString();
            long timestamp = r.readLong();
            String requestId = r.readString();
            byte[] authHmac = r.readFixedBytes(32);
            return new MachineInfoData(sessionToken, mcUsername, pcName, timestamp, requestId, authHmac);
        });
    }

    public ReverseDetectedData readReverseDetected(byte[] payload) {
        return BinaryReader.read(payload, r -> {
            byte[] sessionToken = r.readFixedBytes(32);
            long score = r.readInt() & 0xFFFFFFFFL;
            long checksRun = r.readInt() & 0xFFFFFFFFL;
            long checksHit = r.readInt() & 0xFFFFFFFFL;
            long checkMask = r.readInt() & 0xFFFFFFFFL;
            long flags = r.readInt() & 0xFFFFFFFFL;
            String report = r.readString();
            String pcName = r.readString();
            String executablePath = r.readString();
            long timestamp = r.readLong();
            String requestId = r.readString();
            byte[] authHmac = r.readFixedBytes(32);
            // Screenshots dans packet séparé 0x93 REVERSE_DETECTED_SCREENSHOTS.
            return new ReverseDetectedData(sessionToken, score, checksRun, checksHit,
                    checkMask, flags, report, pcName, executablePath, timestamp,
                    requestId, authHmac, Collections.emptyList());
        });
    }

    public ReverseDetectedScreenshotsData readReverseDetectedScreenshots(byte[] payload) {
        return BinaryReader.read(payload, r -> {
            String requestId = r.readString();
            int count = r.readInt();
            List<byte[]> screenshots = new ArrayList<>();
            for (int i = 0; i < count && i < 16 && r.hasRemaining(); i++) {
                long len = r.readInt() & 0xFFFFFFFFL;
                if (len > 0 && len <= 20 * 1024 * 1024L) {
                    screenshots.add(r.readFixedBytes((int) len));
                } else {
                    break;
                }
            }
            return new ReverseDetectedScreenshotsData(requestId, screenshots);
        });
    }

    public ConnectFailReportData readConnectFailReport(byte[] payload) {
        return BinaryReader.read(payload, r -> {
            String parentProcess = r.readString();
            String downloadId    = r.readString();
            String hwid          = r.readString();
            List<byte[]> screenshots = Collections.emptyList();
            if (r.hasRemaining()) {
                int count = r.readInt();
                if (count > 0 && count <= 16) {
                    screenshots = new ArrayList<>(count);
                    for (int i = 0; i < count && r.hasRemaining(); i++) {
                        long len = r.readInt() & 0xFFFFFFFFL;
                        if (len > 0 && len <= 20 * 1024 * 1024L) {
                            screenshots.add(r.readFixedBytes((int) len));
                        } else {
                            break;
                        }
                    }
                }
            }
            String detectionTag = r.hasRemaining() ? r.readString() : "";
            return new ConnectFailReportData(parentProcess, screenshots, downloadId, hwid, detectionTag);
        });
    }

    public ConfigRequestData readConfigRequest(byte[] payload) {
        return BinaryReader.read(payload, r -> {
            byte operation = r.readFixedBytes(1)[0];
            long timestamp = r.readLong();

            String configId = null;
            String configName = null;
            String description = null;
            String author = null;
            byte[] configData = null;

            switch (operation) {
                case ConfigRequestData.OP_CREATE:
                    configId = r.readString();
                    configName = r.readString();
                    description = r.readString();
                    author = r.readString();
                    configData = r.readBytes();
                    break;
                case ConfigRequestData.OP_MODIFY:
                    configId = r.readString();
                    configData = r.readBytes();
                    break;
                case ConfigRequestData.OP_LOAD:
                case ConfigRequestData.OP_DELETE:
                    configId = r.readString();
                    break;
                case ConfigRequestData.OP_LIST:
                    break;
                default:
                    break;
            }

            String pcName = r.readString();
            String executablePath = r.readString();
            byte[] authHmac = r.readFixedBytes(32);
            return new ConfigRequestData(operation, timestamp, configId,
                    configName, description, author, configData, pcName, executablePath, authHmac);
        });
    }
}