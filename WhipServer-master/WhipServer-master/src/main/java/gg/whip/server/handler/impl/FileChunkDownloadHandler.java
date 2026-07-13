package gg.whip.server.handler.impl;

import fr.whip.api.model.Session;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.FileChunkData;
import gg.whip.server.data.FileChunkMetaData;
import gg.whip.server.data.FileRequestData;
import gg.whip.server.data.RawPacket;
import gg.whip.server.exception.CryptoException;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.*;
import gg.whip.server.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Path;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class FileChunkDownloadHandler extends AbstractSecureHandler {

    private final CryptoService cryptoService;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final BucketService bucketService;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;

    @Override
    protected org.slf4j.Logger getLogger() {
        return log;
    }

    @Override
    protected CryptoService getCryptoService() {
        return cryptoService;
    }

    @Override
    protected AntiReplayService getAntiReplayService() {
        return antiReplayService;
    }

    @Override
    protected PacketWriter getPacketWriter() {
        return packetWriter;
    }

    @Override
    protected PacketSender getPacketSender() {
        return packetSender;
    }

    @Override
    protected AnomalyDetectionService getAnomalyDetectionService() {
        return anomalyDetectionService;
    }

    @Override
    protected UUID getSessionUuid(ClientSession session) {
        return session.getDbSession() != null ? session.getDbSession().getId() : null;
    }

    @Override
    public boolean requiresEncryption() {
        return true;
    }

    @Override
    @Transactional
    public void handle(ClientSession clientSession, RawPacket packet) {
        if (!clientSession.isAuthenticated()) {
            log.warn("File request from unauthenticated session {}", clientSession.getRemoteAddress());
            clientSession.close();
            return;
        }

        if (clientSession.isIpChanged(clientSession.getIp())) {
            log.warn("IP changed during session from {}", clientSession.getRemoteAddress());
            anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.IP_MISMATCH);
            clientSession.close();
            return;
        }

        super.handle(clientSession, packet);
    }

    @Override
    protected void processDecrypted(ClientSession clientSession, byte[] decrypted) {
        try {
            FileRequestData request = packetReader.readFileRequest(decrypted);
            log.debug("Chunked file request from {}: timestamp={}",
                clientSession.getRemoteAddress(), request.timestamp());

            if (!antiReplayService.isTimestampValid(request.timestamp())) {
                log.warn("Invalid timestamp from {}", clientSession.getRemoteAddress());
                anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.INVALID_TIMESTAMP);
                return;
            }

            if (!validateAuthToken(clientSession, request.requestId(), request.authHmac(),
                    request.timestamp(), (short) 0x20)) {
                clientSession.close();
                return;
            }

            Session session = clientSession.getDbSession();
            if (session == null || !session.isActive()) {
                log.warn("Session expired from {}", clientSession.getRemoteAddress());
                return;
            }

            String category = clientSession.nextFileKey();
            if (category == null) {
                log.warn("Download sequence exhausted for {}", clientSession.getRemoteAddress());
                return;
            }

            String productCode = clientSession.getProductCode();
            String username = session.getLicense().getUser().getUsername();
            log.info("Chunked file request #{} resolved to key '{}' for product '{}' from user {} ({})",
                clientSession.getFileDownloadIndex(), category, productCode, username, clientSession.getRemoteAddress());

            Path filePath = bucketService.resolveForSession(category, clientSession);
            if (!bucketService.fileExistsAt(filePath)) {
                log.warn("File not found for key '{}' at {} (requested by {})", category, filePath, username);
                return;
            }

            var blob = bucketService.loadCompressedFromPath(filePath);
            var meta = bucketService.prepareChunkMetaForBlob(category, blob);
            sendChunkMeta(clientSession, meta);

            for (int i = 0; i < meta.chunkCount(); i++) {
                if (!clientSession.getChannel().isActive()) {
                    log.warn("Channel closed during chunked download '{}' at chunk {}/{} for {}",
                            category, i, meta.chunkCount(), clientSession.getRemoteAddress());
                    return;
                }
                FileChunkData chunk = bucketService.encryptChunkFromBytes(
                        category, i, clientSession.getSendKey(), blob.payload());
                sendChunk(clientSession, chunk);
            }

            log.info("Sent chunked file '{}' to {}: {} chunks, original={} bytes, wire={} bytes",
                category, clientSession.getRemoteAddress(), meta.chunkCount(),
                blob.originalSize(), blob.payloadSize());

        } catch (IOException e) {
            log.error("Failed to read file for {}", clientSession.getRemoteAddress(), e);
        } catch (CryptoException e) {
            log.error("Failed to encrypt file for {}", clientSession.getRemoteAddress(), e);
        } catch (Exception e) {
            log.error("Unexpected error processing chunked file request from {}", clientSession.getRemoteAddress(), e);
        }
    }

    private void sendChunkMeta(ClientSession session, FileChunkMetaData meta) {
        byte[] payload = packetWriter.writeFileChunkMeta(meta);
        packetSender.sendEncrypted(session, PacketType.FILE_CHUNK_META, payload);
    }

    private void sendChunk(ClientSession session, FileChunkData chunk) {
        byte[] payload = packetWriter.writeFileChunk(chunk);
        packetSender.sendEncrypted(session, PacketType.FILE_CHUNK, payload);
    }

    @Override
    protected void onNonceReplay(ClientSession session) {
        log.warn("Nonce replay detected from {}", session.getRemoteAddress());
        session.getChannel().close();
    }

    @Override
    protected void onHmacFailed(ClientSession session) {
        log.warn("HMAC verification failed from {}", session.getRemoteAddress());
        session.getChannel().close();
    }

    @Override
    protected void onDecryptionFailed(ClientSession session) {
        log.warn("Decryption failed from {}", session.getRemoteAddress());
        session.getChannel().close();
    }
}
