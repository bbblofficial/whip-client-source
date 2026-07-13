package gg.whip.server.handler.impl;

import fr.whip.api.model.Session;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.HeartbeatData;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.PacketReader;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketType;
import gg.whip.server.network.protocol.PacketWriter;
import gg.whip.server.repository.SessionRepository;
import gg.whip.server.service.AnomalyDetectionService;
import gg.whip.server.service.AntiReplayService;
import gg.whip.server.service.BlacklistService;
import gg.whip.server.service.CryptoService;
import gg.whip.server.service.DiscordWebhookService;
import gg.whip.server.service.SessionService;
import gg.whip.server.service.ViolationType;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class HeartbeatHandler extends AbstractSecureHandler {

    private static final Logger log = LoggerFactory.getLogger(HeartbeatHandler.class);

    private final CryptoService cryptoService;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final BlacklistService blacklistService;
    private final SessionService sessionService;
    private final SessionRepository sessionRepository;
    private final DiscordWebhookService discordWebhook;

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
        return session.getDbSession().getId();
    }

    @Override
    @Transactional
    public void handle(ClientSession session, RawPacket packet) {
        log.debug("Heartbeat received from {} (user: {})",
                 session.getRemoteAddress(),
                 session.getUser() != null ? session.getUser().getUsername() : "unknown");

        if (!session.isAuthenticated()) {
            log.warn("Heartbeat from unauthenticated session {}", session.getRemoteAddress());
            session.close();
            return;
        }

        // Live blacklist gate — bans applied mid-session (e.g. by the
        // reverse-detection handler or an admin via API) take effect at
        // the next heartbeat instead of waiting for the user to reconnect.
        // The blacklist cache is refreshed every 30s in BlacklistService,
        // so an admin-issued ban via the API propagates here within that
        // window. In-process bans (reverse-detected) are visible immediately
        // because BlacklistService.blacklist() updates the in-memory set.
        if (session.getUser() != null && blacklistService.isBlacklisted(session.getUser())) {
            log.warn("Heartbeat from blacklisted user {} (IP: {}) — revoking session",
                    session.getUser().getUsername(), session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.AUTH_FAILED);
            discordWebhook.sendAnomaly("\uD83D\uDD28 Banned user heartbeat",
                    "Blacklisted user attempted to keep session alive",
                    DiscordWebhookService.COLOR_RED,
                    Map.of("IP", session.getRemoteAddress(),
                            "User", session.getUser().getUsername(),
                            "UUID", session.getUser().getId().toString()));
            sendSessionRevoked(session, "Account banned");
            session.close();
            return;
        }

        if (session.isIpChanged(session.getIp())) {
            log.warn("IP changed during session from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.IP_MISMATCH);
            discordWebhook.sendAnomaly("\u26A0\uFE0F Heartbeat Fail", "IP changed during session",
                    DiscordWebhookService.COLOR_ORANGE,
                    Map.of("IP", session.getRemoteAddress(),
                            "User", session.getUser() != null ? session.getUser().getUsername() : "unknown"));
            sendSessionRevoked(session, "IP changed");
            session.close();
            return;
        }

        super.handle(session, packet);
    }

    @Override
    protected void onNonceReplay(ClientSession session) {
        log.warn("Heartbeat nonce replay from {}", session.getRemoteAddress());
        sendNack(session);
    }

    @Override
    protected void onHmacFailed(ClientSession session) {
        log.warn("Heartbeat HMAC failed from {}", session.getRemoteAddress());
        sendNack(session);
    }

    @Override
    protected void onDecryptionFailed(ClientSession session) {
        log.warn("Heartbeat decryption failed from {}", session.getRemoteAddress());
        sendNack(session);
    }

    @Override
    protected void processDecrypted(ClientSession session, byte[] decrypted) {
        HeartbeatData data = packetReader.readHeartbeat(decrypted);
        log.debug("Processing heartbeat - requestId: {}, timestamp: {}",
                 data.requestId(), data.timestamp());

        if (!antiReplayService.isTimestampValid(data.timestamp())) {
            log.warn("Invalid heartbeat timestamp from {} (timestamp: {})",
                    session.getRemoteAddress(), data.timestamp());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.INVALID_TIMESTAMP);
            discordWebhook.sendAnomaly("\u23F0 Heartbeat Fail", "Invalid timestamp",
                    DiscordWebhookService.COLOR_ORANGE,
                    Map.of("IP", session.getRemoteAddress(),
                            "User", session.getUser() != null ? session.getUser().getUsername() : "unknown"));
            sendNack(session);
            return;
        }

        UUID requestId;
        try {
            String rid = data.requestId();
            if (rid.contains("-")) {
                requestId = UUID.fromString(rid);
            } else {
                // C++ sends 32-char hex without dashes
                long msb = Long.parseUnsignedLong(rid.substring(0, 16), 16);
                long lsb = Long.parseUnsignedLong(rid.substring(16, 32), 16);
                requestId = new UUID(msb, lsb);
            }
        } catch (Exception e) {
            log.warn("Invalid request ID from {}", session.getRemoteAddress());
            sendNack(session);
            return;
        }

        UUID sessionId = session.getDbSession().getId();
        if (!antiReplayService.checkAndMarkRequestId(requestId, sessionId)) {
            log.warn("Heartbeat replay from {}", session.getRemoteAddress());
            sendNack(session);
            return;
        }

        if (!cryptoService.verifyChallengeResponse(session.getSessionKey(),
                session.getPendingChallenge(), data.timestamp(), data.challengeResponse())) {
            log.warn("Invalid challenge response from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.CHALLENGE_FAILED);
            discordWebhook.sendAnomaly("\u274C Heartbeat Fail", "Invalid challenge response",
                    DiscordWebhookService.COLOR_RED,
                    Map.of("IP", session.getRemoteAddress(),
                            "User", session.getUser() != null ? session.getUser().getUsername() : "unknown"));
            sendNack(session);
            return;
        }
        log.debug("Challenge response verified for {}", session.getRemoteAddress());

        Session dbSession = session.getDbSession();
        if (dbSession == null) {
            log.info("Session missing for {}", session.getRemoteAddress());
            sendSessionRevoked(session, "Session expired");
            session.close();
            return;
        }
        // Re-fetch from DB so admin actions (close/crash → ended_at)
        // are picked up — the cached in-memory Session never sees those
        // updates otherwise. Without this, an admin-revoked session
        // keeps heartbeating until the natural expires_at timeout.
        // Use the *withGraph* variant so license/user/product/machine
        // are eagerly fetched in this transaction; downstream handlers
        // (ConfigHandler, FileDownloadHandler, …) read license.user
        // off the cached dbSession and would LazyInitException otherwise.
        Session freshSession = sessionRepository.findByIdWithGraph(dbSession.getId()).orElse(null);
        if (freshSession == null || !freshSession.isActive()) {
            log.info("Session revoked/expired (DB) for {} — sending SESSION_REVOKED",
                    session.getRemoteAddress());
            sendSessionRevoked(session, "Session revoked");
            session.close();
            return;
        }
        // Replace cached ref so refreshHeartbeat below saves the up-to-date row.
        session.setDbSession(freshSession);

        sessionService.refreshHeartbeat(freshSession);
        log.debug("Session heartbeat refreshed for {} (user: {})",
                 session.getRemoteAddress(), session.getUser().getUsername());

        byte[] nextChallenge = cryptoService.generateChallenge();
        session.setPendingChallenge(nextChallenge);

        log.info("Heartbeat ACK sent to {} (user: {})",
                session.getRemoteAddress(), session.getUser().getUsername());
        sendAck(session, nextChallenge);
    }

    private void sendAck(ClientSession session, byte[] nextChallenge) {
        byte[] payload = packetWriter.writeHeartbeatAck(nextChallenge, Instant.now().getEpochSecond());
        packetSender.sendEncrypted(session, PacketType.HEARTBEAT_ACK, payload);
    }

    private void sendNack(ClientSession session) {
        byte[] payload = packetWriter.writeHeartbeatNack(Instant.now().getEpochSecond());
        packetSender.sendEncrypted(session, PacketType.HEARTBEAT_ACK, payload);
    }

    private void sendSessionRevoked(ClientSession session, String reason) {
        byte[] payload = packetWriter.writeSessionRevoked(Instant.now().getEpochSecond(), reason);
        packetSender.sendEncrypted(session, PacketType.SESSION_REVOKED, payload);
    }
}
