package gg.whip.server.handler.impl;

import fr.whip.api.model.Session;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.FileChunkData;
import gg.whip.server.data.FileChunkMetaData;
import gg.whip.server.data.FileRequestData;
import gg.whip.server.data.FileResponseData;
import gg.whip.server.data.RawPacket;
import gg.whip.server.exception.CryptoException;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.*;
import gg.whip.server.service.*;
import gg.whip.server.service.ViolationType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;

@Slf4j
@Component
@RequiredArgsConstructor
public class FileDownloadHandler extends AbstractSecureHandler {

    private final CryptoService cryptoService;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final BucketService bucketService;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;
    private final AuthTagValidator authTagValidator;
    private final DiscordWebhookService discordWebhook;
    private final WatermarkService watermarkService;
    @org.springframework.beans.factory.annotation.Qualifier("downloadExecutor")
    private final ExecutorService downloadExecutor;

    @Override
    protected Logger getLogger() {
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
    public void handle(ClientSession clientSession, RawPacket packet) {
        if (!clientSession.isAuthenticated()) {
            log.warn("File request from unauthenticated session {}", clientSession.getRemoteAddress());
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
            FileRequestData request = packetReader.readFileRequest(decrypted);
            log.debug("File request from {}: timestamp={}",
                clientSession.getRemoteAddress(), request.timestamp());

            if (!antiReplayService.isTimestampValid(request.timestamp())) {
                log.warn("Invalid timestamp from {}", clientSession.getRemoteAddress());
                anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.INVALID_TIMESTAMP);
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.INVALID_TIMESTAMP.getCode()));
                return;
            }

            if (!validateAuthToken(clientSession, request.requestId(), request.authHmac(),
                    request.timestamp(), (short) 0x20)) {
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.INVALID_TOKEN.getCode()));
                clientSession.close();
                return;
            }

            // Phase 1+2 auth_tag — HMAC(SHA256(authSalt||algoSeed), pcName||score).
            if (clientSession.getDownload() != null
                    && clientSession.getDownload().getAuthSalt() != null
                    && clientSession.getDownload().getAlgoSeed() != null
                    && clientSession.getDownload().getExpectedFingerprint() != null) {
                String pcName = request.pcName() != null ? request.pcName() : "";
                if (!authTagValidator.validate(clientSession.getDownload().getAuthSalt(),
                        clientSession.getDownload().getAlgoSeed(),
                        clientSession.getDownload().getExpectedFingerprint(),
                        pcName, request.authTag())) {
                    log.error("EXE TAMPERED — auth_tag mismatch on FILE_REQUEST from {}",
                            clientSession.getRemoteAddress());
                    anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.AUTH_TAG_MISMATCH);
                    fr.whip.api.model.User u = clientSession.getUser();
                    Map<String, String> tagFields = new LinkedHashMap<>();
                    tagFields.put("IP", clientSession.getRemoteAddress());
                    tagFields.put("User", u != null ? u.getUsername() : "?");
                    tagFields.put("Discord", u != null && u.getDiscordId() != null ? "<@" + u.getDiscordId() + ">" : "N/A");
                    if (pcName != null && !pcName.isBlank()) tagFields.put("Nom du PC", pcName);
                    tagFields.put("Suspected", "Loader patched between INIT and FILE_REQUEST — DLL not served");
                    discordWebhook.sendFail("\uD83D\uDEA8 EXE TAMPERED",
                            "Loader auth_tag mismatch on FILE_REQUEST — DLL refused",
                            DiscordWebhookService.COLOR_RED, tagFields);
                    clientSession.setBlockReportReason("EXE TAMPERED (FILE_REQUEST)");
                    clientSession.setBlockReportPcName(pcName);
                    sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.ANOMALY_DETECTED.getCode()));
                    clientSession.close();
                    return;
                }
            }

            Session session = clientSession.getDbSession();
            if (session == null || !session.isActive()) {
                log.warn("Session expired from {}", clientSession.getRemoteAddress());
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.SESSION_EXPIRED.getCode()));
                return;
            }

            // Resolve file category from session download sequence (zero trust — no key from client)
            String category = clientSession.nextFileKey();
            if (category == null) {
                log.warn("Download sequence exhausted for {}", clientSession.getRemoteAddress());
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.INVALID_FILE_REQUEST.getCode()));
                return;
            }

            String productCode = clientSession.getProductCode();
            String username = session.getLicense().getUser().getUsername();
            log.info("File request #{} resolved to key '{}' for product '{}' from user {} ({})",
                clientSession.getFileDownloadIndex(), category, productCode, username, clientSession.getRemoteAddress());

            Path resolvedPath = bucketService.resolveForSession(category, clientSession);
            if (!bucketService.fileExistsAt(resolvedPath)) {
                log.warn("File not found for key '{}' at {} (requested by {})", category, resolvedPath, username);
                sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.FILE_NOT_FOUND.getCode()));
                return;
            }

            // Submit heavy work (file read + watermark + compress + chunk loop) to a
            // dedicated executor so the Netty I/O thread is freed immediately. While
            // the download runs in the worker thread, the event loop can receive and
            // process other packets on this channel (e.g. REVERSE_DETECTED).
            final String finalCategory = category;
            final Path finalPath = resolvedPath;
            final String finalUsername = username;
            final FileRequestData finalRequest = request;
            final boolean dll = isDllKey(category);
            final boolean chunked = isChunkedKey(category);

            downloadExecutor.submit(() -> {
                try {
                    if (chunked) {
                        if (dll) {
                            handleWatermarkedDllDownload(clientSession, finalCategory, finalPath,
                                    finalUsername, finalRequest);
                        } else {
                            handleChunkedDownload(clientSession, finalCategory, finalPath, finalUsername);
                        }
                    } else {
                        handleLegacyDownload(clientSession, finalCategory, finalPath, finalUsername);
                    }
                } catch (IOException e) {
                    log.error("Failed to read file for {}", clientSession.getRemoteAddress(), e);
                    sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.DOWNLOAD_FAILED.getCode()));
                } catch (CryptoException e) {
                    log.error("Failed to encrypt file for {}", clientSession.getRemoteAddress(), e);
                    sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.SERVER_ERROR.getCode()));
                } catch (Exception e) {
                    log.error("Unexpected error in download for {}", clientSession.getRemoteAddress(), e);
                    sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.SERVER_ERROR.getCode()));
                }
            });

        } catch (Exception e) {
            log.error("Unexpected error processing file request from {}", clientSession.getRemoteAddress(), e);
            sendErrorResponse(clientSession, String.valueOf(ServerErrorCode.SERVER_ERROR.getCode()));
        }
    }

    private boolean isChunkedKey(String key) {
        return key.endsWith("-dll") || key.equals("beta-dll");
    }

    private boolean isDllKey(String key) {
        return key.endsWith("-dll") || key.equals("beta-dll");
    }

    private void handleWatermarkedDllDownload(ClientSession clientSession, String category,
                                              Path filePath, String username,
                                              FileRequestData request)
            throws IOException, CryptoException {
        byte[] dllBytes = java.nio.file.Files.readAllBytes(filePath);

        Session dbSession = clientSession.getDbSession();
        java.util.UUID downloadId = clientSession.getDownload() != null
                ? clientSession.getDownload().getId() : null;
        String wmSession = watermarkService.patchAndPersist(dllBytes,
                clientSession.getUser(),
                dbSession != null && dbSession.getMachine() != null
                        ? dbSession.getMachine().getHwid() : null,
                clientSession.getRemoteAddress(),
                request.pcName(),
                downloadId);

        if (wmSession != null) {
            log.info("DLL '{}' watermarked with session {} for {}",
                    category, wmSession, username);
        } else {
            log.warn("DLL '{}' had no watermark slot — shipping un-traceable",
                    category);
        }

        // Compress *after* watermarking (the watermark is per-session, can't
        // share a cache anyway). The chunked + encrypted blob the loader
        // receives is the DEFLATE output; it inflates back to the watermarked
        // DLL on its end, watermark intact.
        var blob = bucketService.compressIfWorthwhile(dllBytes);
        var meta = bucketService.prepareChunkMetaForBlob(category, blob);
        sendChunkMeta(clientSession, meta);

        for (int i = 0; i < meta.chunkCount(); i++) {
            if (!clientSession.getChannel().isActive()) {
                log.warn("Channel closed during watermarked download '{}' at chunk {}/{} for {}",
                        category, i, meta.chunkCount(), clientSession.getRemoteAddress());
                return;
            }
            var chunk = bucketService.encryptChunkFromBytes(category, i,
                    clientSession.getSendKey(), blob.payload());
            sendChunk(clientSession, chunk);
        }

        log.info("Sent watermarked DLL '{}' to {}: {} chunks, original={} bytes, wire={} bytes",
                category, clientSession.getRemoteAddress(), meta.chunkCount(),
                blob.originalSize(), blob.payloadSize());
    }

    private void handleChunkedDownload(ClientSession clientSession, String category, Path filePath, String username)
            throws IOException, CryptoException {
        // Static path (no watermark) — use the on-disk .z cache so we don't
        // re-DEFLATE on every download of an unchanged file.
        var blob = bucketService.loadCompressedFromPath(filePath);
        var meta = bucketService.prepareChunkMetaForBlob(category, blob);
        sendChunkMeta(clientSession, meta);

        for (int i = 0; i < meta.chunkCount(); i++) {
            if (!clientSession.getChannel().isActive()) {
                log.warn("Channel closed during chunked download '{}' at chunk {}/{} for {}",
                        category, i, meta.chunkCount(), clientSession.getRemoteAddress());
                return;
            }
            var chunk = bucketService.encryptChunkFromBytes(category, i,
                    clientSession.getSendKey(), blob.payload());
            sendChunk(clientSession, chunk);
        }

        log.info("Sent chunked file '{}' to {}: {} chunks, original={} bytes, wire={} bytes",
                category, clientSession.getRemoteAddress(), meta.chunkCount(),
                blob.originalSize(), blob.payloadSize());
    }

    private void handleLegacyDownload(ClientSession clientSession, String category, Path filePath, String username)
            throws IOException, CryptoException {
        byte[] raw = java.nio.file.Files.readAllBytes(filePath);
        int originalSize = raw.length;
        var blob = bucketService.compressIfWorthwhile(raw);

        // Encrypt the (possibly compressed) blob in one shot. The wire
        // payload after AES-GCM is nonce(12) || ciphertext || tag(16);
        // BucketService.encrypt prepends the nonce, GCM appends the tag.
        byte[] encryptedFile = bucketService.encryptOneShot(blob.payload(), clientSession.getSendKey());

        FileResponseData response = blob.compressed()
                ? FileResponseData.successCompressed(encryptedFile, originalSize, blob.payloadSize())
                : FileResponseData.success(encryptedFile, originalSize);
        sendFileResponse(clientSession, response);

        log.info("File '{}' sent to {}: original={} bytes, wire={} bytes ({}compressed)",
            category, clientSession.getRemoteAddress(), originalSize,
            blob.payloadSize(), blob.compressed() ? "" : "un");
    }

    private void sendFileResponse(ClientSession session, FileResponseData response) {
        byte[] payload = packetWriter.writeFileResponse(response);
        packetSender.sendEncrypted(session, PacketType.FILE_RESPONSE, payload);
    }

    private void sendErrorResponse(ClientSession session, String errorMessage) {
        FileResponseData response = FileResponseData.error(errorMessage);
        sendFileResponse(session, response);
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