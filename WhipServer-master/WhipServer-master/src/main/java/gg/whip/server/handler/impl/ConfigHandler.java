package gg.whip.server.handler.impl;

import fr.whip.api.model.Session;
import fr.whip.api.model.User;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.ConfigRequestData;
import gg.whip.server.data.ConfigResponseData;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.*;
import gg.whip.server.service.AnomalyDetectionService;
import gg.whip.server.service.AntiReplayService;
import gg.whip.server.service.ConfigStorageService;
import gg.whip.server.service.CryptoService;
import gg.whip.server.service.ViolationType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class ConfigHandler extends AbstractSecureHandler {

    private final CryptoService cryptoService;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final ConfigStorageService configStorageService;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;

    @Override
    protected Logger getLogger() { return log; }

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
    @Transactional
    public void handle(ClientSession clientSession, RawPacket packet) {
        if (!clientSession.isAuthenticated()) {
            log.warn("Config request from unauthenticated session {}", clientSession.getRemoteAddress());
            clientSession.close();
            return;
        }
        super.handle(clientSession, packet);
    }

    @Override
    protected void processDecrypted(ClientSession clientSession, byte[] decrypted) {
        try {
            ConfigRequestData request = packetReader.readConfigRequest(decrypted);
            log.debug("Config request from {}: op={}, configId={}",
                clientSession.getRemoteAddress(), request.operation(), request.configId());

            if (!antiReplayService.isTimestampValid(request.timestamp())) {
                log.warn("Invalid timestamp from {}", clientSession.getRemoteAddress());
                anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.INVALID_TIMESTAMP);
                sendResponse(clientSession, ConfigResponseData.error(request.operation(), "Invalid timestamp"));
                return;
            }

            // Auth HMAC: HMAC-SHA256(userSecret, packetType(0x80) || timestamp)
            // No requestId — anti-replay handled by packet nonce + timestamp validation
            byte[] userSecret = clientSession.getUserSecret();
            if (userSecret == null) {
                log.warn("Missing user secret for {}", clientSession.getRemoteAddress());
                anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.AUTH_FAILED);
                sendResponse(clientSession, ConfigResponseData.error(request.operation(), "Authentication failed"));
                clientSession.close();
                return;
            }

            if (!cryptoService.verifyAuthHmac(userSecret, (short) 0x80, "", request.timestamp(), request.authHmac())) {
                log.warn("Auth HMAC verification failed from {}", clientSession.getRemoteAddress());
                anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.HMAC_FAILED);
                sendResponse(clientSession, ConfigResponseData.error(request.operation(), "Authentication failed"));
                clientSession.close();
                return;
            }

            Session session = clientSession.getDbSession();
            if (session == null || !session.isActive()) {
                sendResponse(clientSession, ConfigResponseData.error(request.operation(), "Session expired"));
                return;
            }

            User user = session.getLicense().getUser();

            ConfigResponseData response = switch (request.operation()) {
                case ConfigRequestData.OP_CREATE -> configStorageService.create(
                        user, request.configId(), request.configName(),
                        request.description(), request.author(), request.configData());
                case ConfigRequestData.OP_LOAD -> configStorageService.load(user, request.configId());
                case ConfigRequestData.OP_DELETE -> configStorageService.delete(user, request.configId());
                case ConfigRequestData.OP_MODIFY -> configStorageService.update(user, request.configId(), request.configData());
                case ConfigRequestData.OP_LIST -> configStorageService.listForUser(user);
                default -> ConfigResponseData.error(request.operation(), "Unknown operation");
            };

            sendResponse(clientSession, response);

        } catch (Exception e) {
            log.error("Error processing config request from {}", clientSession.getRemoteAddress(), e);
            sendResponse(clientSession, ConfigResponseData.error((byte) -1, "Internal server error"));
        }
    }

    private void sendResponse(ClientSession session, ConfigResponseData response) {
        byte[] payload = packetWriter.writeConfigResponse(response);
        packetSender.sendEncrypted(session, PacketType.CONFIG_RESPONSE, payload);
    }

    @Override
    protected void onNonceReplay(ClientSession session) {
        log.warn("Nonce replay detected from {}", session.getRemoteAddress());
        sendResponse(session, ConfigResponseData.error((byte) -1, "Nonce replay"));
        session.getChannel().close();
    }

    @Override
    protected void onHmacFailed(ClientSession session) {
        log.warn("HMAC verification failed from {}", session.getRemoteAddress());
        sendResponse(session, ConfigResponseData.error((byte) -1, "Invalid signature"));
        session.getChannel().close();
    }

    @Override
    protected void onDecryptionFailed(ClientSession session) {
        log.warn("Decryption failed from {}", session.getRemoteAddress());
        sendResponse(session, ConfigResponseData.error((byte) -1, "Decryption failed"));
        session.getChannel().close();
    }
}
