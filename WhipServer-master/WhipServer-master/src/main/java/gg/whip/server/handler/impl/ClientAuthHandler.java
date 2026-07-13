package gg.whip.server.handler.impl;

import fr.whip.api.model.License;
import fr.whip.api.model.Machine;
import fr.whip.api.model.Session;
import fr.whip.api.model.User;
import gg.whip.server.data.ClientAuthData;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.PacketReader;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketType;
import gg.whip.server.network.protocol.PacketWriter;
import gg.whip.server.service.*;
import gg.whip.server.service.ViolationType;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Component
@RequiredArgsConstructor
public class ClientAuthHandler extends AbstractSecureHandler {

    private static final Logger log = LoggerFactory.getLogger(ClientAuthHandler.class);
    private static final int PERM_BASIC = 0x01;

    private final CryptoService cryptoService;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final LicenseService licenseService;
    private final MachineService machineService;
    private final SessionService sessionService;
    private final DiscordWebhookService discordWebhook;
    private final AuthTagValidator authTagValidator;
    private final AuditService auditService;

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
        return UUID.nameUUIDFromBytes(session.getTempSessionId().getBytes());
    }

    @Override
    @Transactional
    public void handle(ClientSession session, RawPacket packet) {
        if (session.getState() != ClientSession.SessionState.HELLO_DONE) {
            log.warn("CLIENT_AUTH in wrong state from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.INVALID_STATE);
            sendError(session, 1, "Invalid state");
            session.close();
            return;
        }

        super.handle(session, packet);
    }

    @Override
    @Transactional
    protected void processDecrypted(ClientSession session, byte[] decrypted) {
        ClientAuthData data = packetReader.readClientAuth(decrypted);

        // SECURITY: Validate timestamp (nonce replay already checked in AbstractSecureHandler)
        if (!antiReplayService.isTimestampValid(data.timestamp())) {
            log.warn("Invalid timestamp from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.INVALID_TIMESTAMP);
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u23F0 Timestamp Fail", "Invalid timestamp on CLIENT_AUTH",
                    DiscordWebhookService.COLOR_RED, fields);
            sendClientAuthError(session, String.valueOf(ServerErrorCode.INVALID_TIMESTAMP.getCode()));
            return;
        }

        Optional<TemporaryClientToken> tokenOpt = sessionService.findTemporaryClientToken(data.temporaryClientToken());
        if (tokenOpt.isEmpty()) {
            log.warn("Invalid temporary token from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.INVALID_TOKEN);
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u274C Auth Failed", "Invalid temporary token",
                    DiscordWebhookService.COLOR_RED, fields);
            sendClientAuthError(session, String.valueOf(ServerErrorCode.INVALID_TOKEN.getCode()));
            return;
        }

        TemporaryClientToken tempToken = tokenOpt.get();

        if (tempToken.isExpired()) {
            log.warn("Expired temporary token from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.INVALID_TOKEN);
            sessionService.deleteTemporaryClientToken(tempToken);
            sendClientAuthError(session, String.valueOf(ServerErrorCode.INVALID_TOKEN.getCode()));
            return;
        }

        if (!tempToken.getIpAddress().equals(session.getIp())) {
            log.warn("IP mismatch for temporary token from {} (expected {}, got {})",
                    session.getRemoteAddress(), tempToken.getIpAddress(), session.getIp());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.IP_MISMATCH);
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            fields.put("Expected IP", tempToken.getIpAddress());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u274C Auth Failed", "IP address mismatch",
                    DiscordWebhookService.COLOR_RED, fields);
            sendClientAuthError(session, String.valueOf(ServerErrorCode.SUSPICIOUS_ACTIVITY.getCode()));
            return;
        }

        if (!tempToken.getHwid().equals(data.hwid())) {
            log.warn("HWID mismatch for temporary token from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.HWID_MISMATCH);
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u274C Auth Failed", "HWID mismatch",
                    DiscordWebhookService.COLOR_RED, fields);
            sendClientAuthError(session, String.valueOf(ServerErrorCode.HWID_MISMATCH.getCode()));
            return;
        }

        // Single-use attestation token: proves the loader→client chain.
        // The server issues this at PRODUCT_SELECT and the loader forwards it
        // to the injected client over IPC. If consumed already, or if it
        // doesn't match the bytes we issued, reject.
        if (tempToken.isAttestationConsumed()) {
            log.warn("Attestation token already consumed from {} (replay attempt)", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.ATTESTATION_TOKEN_INVALID);
            sessionService.deleteTemporaryClientToken(tempToken);
            sendClientAuthError(session, String.valueOf(ServerErrorCode.INVALID_TOKEN.getCode()));
            return;
        }
        if (!java.security.MessageDigest.isEqual(
                tempToken.getClientAttestationToken(), data.clientAttestationToken())) {
            log.warn("Attestation token mismatch from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.ATTESTATION_TOKEN_INVALID);
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u274C Auth Failed", "Attestation token mismatch",
                    DiscordWebhookService.COLOR_RED, fields);
            sendClientAuthError(session, String.valueOf(ServerErrorCode.INVALID_TOKEN.getCode()));
            return;
        }
        tempToken.setAttestationConsumed(true);

        // Phase 1+2: validate the loader's auth_tag forwarded by the client.
        // Computed by the loader on the temporaryClientToken[32] using
        // SHA256(authSalt || algoSeed) baked in the loader overlay.
        if (tempToken.getAuthSalt() != null && tempToken.getAlgoSeed() != null
                && tempToken.getExpectedFingerprint() != null) {
            if (!authTagValidator.validate(tempToken.getAuthSalt(), tempToken.getAlgoSeed(),
                    tempToken.getExpectedFingerprint(),
                    data.temporaryClientToken(), data.loaderAuthTag())) {
                log.error("EXE TAMPERED — loader auth_tag mismatch on CLIENT_AUTH from {} (user: {})",
                        session.getRemoteAddress(), tempToken.getUser().getUsername());
                anomalyDetectionService.recordViolation(session.getIp(), ViolationType.AUTH_TAG_MISMATCH);
                sessionService.deleteTemporaryClientToken(tempToken);
                Map<String, String> tagFields = new LinkedHashMap<>();
                tagFields.put("IP", session.getRemoteAddress());
                tagFields.put("User", tempToken.getUser().getUsername());
                tagFields.put("Discord", tempToken.getUser().getDiscordId() != null
                        ? "<@" + tempToken.getUser().getDiscordId() + ">" : "N/A");
                tagFields.put("HWID", tempToken.getHwid());
                if (data.pcName() != null && !data.pcName().isBlank()) tagFields.put("Nom du PC", data.pcName());
                if (data.executablePath() != null && !data.executablePath().isBlank()) tagFields.put("Executable", data.executablePath());
                tagFields.put("Suspected", "Loader patched between PRODUCT_SELECT and CLIENT_AUTH");
                discordWebhook.sendFail("\uD83D\uDEA8 EXE TAMPERED",
                        "Loader auth_tag mismatch on CLIENT_AUTH — altered binary",
                        DiscordWebhookService.COLOR_RED, tagFields);
                session.setBlockReportReason("EXE TAMPERED (CLIENT_AUTH)");
                session.setBlockReportUsername(tempToken.getUser().getUsername());
                session.setBlockReportPcName(data.pcName());
                session.setBlockReportExe(data.executablePath());
                sendClientAuthError(session, String.valueOf(ServerErrorCode.ANOMALY_DETECTED.getCode()));
                session.close();
                return;
            }
        }

        User user = tempToken.getUser();
        License license = tempToken.getLicense();
        Machine machine = tempToken.getMachine();

        if (machine.getRevokedAt() != null) {
            sendClientAuthError(session, String.valueOf(ServerErrorCode.MACHINE_REVOKED.getCode()));
            return;
        }

        machineService.updateLastSeen(machine);

        if (sessionService.hasActiveSessionForMachine(machine)) {
            log.warn("Multi-instance detected for machine {} (user: {})", machine.getHwid(), user.getUsername());
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            fields.put("User", user.getUsername());
            fields.put("HWID", machine.getHwid());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u26A0\uFE0F Multi-Instance Detected", "Already connected from this machine",
                    DiscordWebhookService.COLOR_RED, fields);
            sendClientAuthError(session, String.valueOf(ServerErrorCode.SESSION_ALREADY_EXISTS.getCode()));
            return;
        }

        if (sessionService.hasReachedSessionLimit(license)) {
            Map<String, String> limitFields = new LinkedHashMap<>();
            limitFields.put("IP", session.getRemoteAddress());
            limitFields.put("User", user.getUsername());
            limitFields.put("HWID", machine.getHwid());
            if (data.pcName() != null && !data.pcName().isBlank()) limitFields.put("Nom du PC", data.pcName());
            discordWebhook.sendFail("⚠️ Session Limit", "Session limit reached for license",
                    DiscordWebhookService.COLOR_RED, limitFields);
            sendClientAuthError(session, String.valueOf(ServerErrorCode.SESSION_ALREADY_EXISTS.getCode()));
            return;
        }

        Session dbSession = sessionService.create(
                license, machine,
                session.getIp(), session.getSessionKey()
        );

        byte[] challenge = cryptoService.generateChallenge();
        byte[] sessionToken = cryptoService.generateSessionToken();
        byte[] userSecret = cryptoService.generateRandomBytes(32);
        session.setUserSecret(userSecret);
        // Persist the 32-byte sessionToken on the session so SettingMutateHandler
        // can fold it into the canonical Ed25519 payload (the client also has
        // it — sent below — and rebuilds the same payload to verify).
        session.setSessionToken(sessionToken);

        session.setUser(user);
        session.setLicense(license);
        session.setMachine(machine);
        session.setDbSession(dbSession);
        session.setProductCode(tempToken.getProductCode());
        session.setPendingChallenge(challenge);
        session.setPermissions(PERM_BASIC);
        session.setState(ClientSession.SessionState.AUTHENTICATED);

        sessionService.deleteTemporaryClientToken(tempToken);

        sendClientAuthSuccess(session, sessionToken, PERM_BASIC,
                dbSession.getExpiresAt().getEpochSecond(), challenge, user.getUsername(), userSecret);

        log.info("Client auth success for {} (user: {}, product: {})",
                session.getRemoteAddress(), user.getUsername(), tempToken.getProductCode());

        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("Pseudo", user.getUsername());
        fields.put("UUID", user.getId().toString());
        fields.put("IP", session.getRemoteAddress());
        fields.put("HWID", machine.getHwid());
        fields.put("Discord", user.getDiscordId() != null ? "<@" + user.getDiscordId() + ">" : "N/A");
        fields.put("Produit", license.getProduct().getName());
        fields.put("Expiration", license.getExpiresAt() != null ? license.getExpiresAt().toString() : "Lifetime");
        fields.put("Nom du PC", machine.getPcName() != null ? machine.getPcName() : "N/A");
        discordWebhook.sendSuccess("\u2705 Auth Success", "Client authenticated successfully",
                DiscordWebhookService.COLOR_GREEN, fields);
        auditService.event("auth.success", "auth", user.getId(), session.getIp(),
                "Auth OK \u2014 produit=" + session.getProductCode() + " \u2014 " + user.getUsername());
    }

    private void sendClientAuthSuccess(ClientSession session, byte[] token, int permissions, long expiresAt, byte[] challenge, String username, byte[] userSecret) {
        byte[] payload = packetWriter.writeClientAuthSuccessWithSecret(token, permissions, expiresAt, challenge, username, userSecret);
        packetSender.sendEncrypted(session, PacketType.CLIENT_AUTH_RESPONSE, payload);
    }

    private void sendClientAuthError(ClientSession session, String message) {
        byte[] payload = packetWriter.writeClientAuthError(message);
        packetSender.sendEncrypted(session, PacketType.CLIENT_AUTH_RESPONSE, payload);
        String username = session.getUser() != null ? session.getUser().getUsername() : "?";
        UUID uid = session.getUser() != null ? session.getUser().getId() : null;
        auditService.event("auth.failed", "auth", uid, session.getIp(),
                "Échec auth — code=" + message + " user=" + username);
    }
}
