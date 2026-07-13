package gg.whip.server.handler.impl;

import fr.whip.api.model.Session;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.FileResponseData;
import gg.whip.server.data.KeyedFileRequestData;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.*;
import gg.whip.server.service.*;
import gg.whip.server.service.ViolationType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeyedFileDownloadHandler extends AbstractSecureHandler {

    private final CryptoService cryptoService;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final BucketService bucketService;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;

    @Override
    protected org.slf4j.Logger getLogger() { return log; }

    @Override
    protected CryptoService getCryptoService() { return cryptoService; }

    @Override
    protected AntiReplayService getAntiReplayService() { return antiReplayService; }

    @Override
    protected PacketWriter getPacketWriter() { return packetWriter; }

    @Override
    protected PacketSender getPacketSender() { return packetSender; }

    @Override
    protected AnomalyDetectionService getAnomalyDetectionService() { return anomalyDetectionService; }

    @Override
    protected UUID getSessionUuid(ClientSession session) {
        return session.getDbSession() != null ? session.getDbSession().getId() : null;
    }

    @Override
    public boolean requiresEncryption() { return true; }

    @Override
    @Transactional
    public void handle(ClientSession clientSession, RawPacket packet) {
        if (!clientSession.isAuthenticated()) {
            log.warn("Keyed file request from unauthenticated session {}", clientSession.getRemoteAddress());
            clientSession.close();
            return;
        }

        if (clientSession.isIpChanged(clientSession.getIp())) {
            log.warn("IP changed during session from {}", clientSession.getRemoteAddress());
            anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.IP_MISMATCH);
            sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.SUSPICIOUS_ACTIVITY.getCode()));
            clientSession.close();
            return;
        }

        super.handle(clientSession, packet);
    }

    @Override
    protected void processDecrypted(ClientSession clientSession, byte[] decrypted) {
        try {
            KeyedFileRequestData request = packetReader.readKeyedFileRequest(decrypted);
            log.info("Keyed file request from {}: key='{}', timestamp={}",
                clientSession.getRemoteAddress(), request.key(), request.timestamp());

            if (!antiReplayService.isTimestampValid(request.timestamp())) {
                log.warn("Invalid timestamp from {}", clientSession.getRemoteAddress());
                anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.INVALID_TIMESTAMP);
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.INVALID_TIMESTAMP.getCode()));
                return;
            }

            if (!validateAuthToken(clientSession, request.requestId(), request.authHmac(),
                    request.timestamp(), (short) 0x22)) {
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.INVALID_TOKEN.getCode()));
                clientSession.close();
                return;
            }

            Session session = clientSession.getDbSession();
            if (session == null || !session.isActive()) {
                log.warn("Session expired from {}", clientSession.getRemoteAddress());
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.SESSION_EXPIRED.getCode()));
                return;
            }

            String key = request.key();

            // ZERO-TRUST: Validate that the requested key is authorized for this session
            if (!clientSession.isFileKeyAuthorized(key)) {
                log.warn("SECURITY: Unauthorized file key '{}' from {}", key, clientSession.getRemoteAddress());
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.INSUFFICIENT_PERMISSIONS.getCode()));
                clientSession.close();
                return;
            }

            if (!bucketService.fileExists(key)) {
                log.warn("File not found for '{}' from {}", key, clientSession.getRemoteAddress());
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.FILE_NOT_FOUND.getCode()));
                return;
            }

            byte[] fileBytes = bucketService.readRawFile(key);
            int originalSize = fileBytes.length;

            // Single-shot path is used by the in-game DLL for mappings /
            // versions / configs — those grow fast (mappings can hit
            // several MB after a few engine versions). Same DEFLATE
            // pass + threshold logic as the chunked path; receiver
            // inflates if compressed=true, raw bytes otherwise.
            var blob = bucketService.compressIfWorthwhile(fileBytes);

            FileResponseData response = blob.compressed()
                    ? FileResponseData.successCompressed(blob.payload(), originalSize, blob.payloadSize())
                    : FileResponseData.success(blob.payload(), originalSize);
            byte[] payload = packetWriter.writeFileResponse(response);
            packetSender.sendEncrypted(clientSession, PacketType.KEYED_FILE_RESPONSE, payload);

            log.info("Keyed file '{}' sent to {}: original={} bytes, wire={} bytes ({}compressed)",
                key, clientSession.getRemoteAddress(), originalSize,
                blob.payloadSize(), blob.compressed() ? "" : "un");

        } catch (IOException e) {
            log.error("Failed to read file for {}", clientSession.getRemoteAddress(), e);
            sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.DOWNLOAD_FAILED.getCode()));
        } catch (Exception e) {
            log.error("Unexpected error for keyed file request from {}", clientSession.getRemoteAddress(), e);
            sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.SERVER_ERROR.getCode()));
        }
    }

    private void sendErrorResponse(ClientSession session, String errorMessage) {
        FileResponseData response = FileResponseData.error(errorMessage);
        byte[] payload = packetWriter.writeFileResponse(response);
        packetSender.sendEncrypted(session, PacketType.KEYED_FILE_RESPONSE, payload);
    }

    @Override
    protected void onNonceReplay(ClientSession session) {
        log.warn("Nonce replay detected from {}", session.getRemoteAddress());
        sendErrorResponse(session, String.valueOf(ServerErrorCode.NONCE_REPLAY_DETECTED.getCode()));
        session.getChannel().close();
    }

    @Override
    protected void onHmacFailed(ClientSession session) {
        log.warn("HMAC verification failed from {}", session.getRemoteAddress());
        sendErrorResponse(session, String.valueOf(ServerErrorCode.INVALID_REQUEST.getCode()));
        session.getChannel().close();
    }

    @Override
    protected void onDecryptionFailed(ClientSession session) {
        log.warn("Decryption failed from {}", session.getRemoteAddress());
        sendErrorResponse(session, String.valueOf(ServerErrorCode.SERVER_ERROR.getCode()));
        session.getChannel().close();
    }
}
