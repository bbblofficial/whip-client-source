package gg.whip.server.handler.impl;

import fr.whip.api.model.License;
import fr.whip.api.model.Machine;
import fr.whip.api.model.Session;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.ProductSelectData;
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

import java.util.*;

@Component
@RequiredArgsConstructor
public class ProductSelectHandler extends AbstractSecureHandler {

    private static final Logger log = LoggerFactory.getLogger(ProductSelectHandler.class);
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
    private final BucketService bucketService;
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
        return UUID.nameUUIDFromBytes(session.getTempSessionId().getBytes());
    }

    @Override
    @Transactional
    public void handle(ClientSession session, RawPacket packet) {
        if (session.getState() != ClientSession.SessionState.INIT_DONE) {
            log.warn("PRODUCT_SELECT in wrong state from {}", session.getRemoteAddress());
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
        ProductSelectData data = packetReader.readProductSelect(decrypted);

        // SECURITY: Validate timestamp (nonce replay already checked in AbstractSecureHandler)
        if (!antiReplayService.isTimestampValid(data.timestamp())) {
            log.warn("Invalid timestamp from {}", session.getRemoteAddress());
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            fields.put("User", session.getUser().getUsername());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u23F0 Timestamp Fail", "Invalid timestamp on PRODUCT_SELECT",
                    DiscordWebhookService.COLOR_RED, fields);
            sendAuthError(session, ServerErrorCode.INVALID_TIMESTAMP.getCode(), ServerErrorCode.INVALID_TIMESTAMP.getInternalDescription());
            return;
        }

        Optional<License> licenseOpt = licenseService.findValidLicense(session.getUser(), data.productCode());
        if (licenseOpt.isEmpty()) {
            log.warn("Invalid product {} for user {} from {}",
                    data.productCode(), session.getUser().getUsername(), session.getRemoteAddress());
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            fields.put("User", session.getUser().getUsername());
            fields.put("Product", data.productCode());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u274C Product Select Failed", "Invalid product selection",
                    DiscordWebhookService.COLOR_RED, fields);
            sendAuthError(session, ServerErrorCode.PRODUCT_NOT_FOUND.getCode(), ServerErrorCode.PRODUCT_NOT_FOUND.getInternalDescription());
            return;
        }
        License license = licenseOpt.get();

        // Déterminer la machine selon le mode d'authentification
        Machine machine;
        if (session.getMachine() != null) {
            // Mode HWID: machine déjà trouvée dans InitHandler
            machine = session.getMachine();
            if (machine.getRevokedAt() != null) {
                sendAuthError(session, ServerErrorCode.MACHINE_REVOKED.getCode(), ServerErrorCode.MACHINE_REVOKED.getInternalDescription());
                return;
            }
            machineService.updateLastSeen(machine);
        } else if (session.getDownload() != null) {
            // Mode Download ID: chercher ou créer la machine avec le vrai HWID
            String hwid = session.getHwid();  // Use real HWID from init, not downloadId
            if (hwid == null || hwid.isBlank()) {
                log.error("Missing HWID in session for {}", session.getRemoteAddress());
                sendAuthError(session, ServerErrorCode.INVALID_REQUEST.getCode(), ServerErrorCode.INVALID_REQUEST.getInternalDescription());
                return;
            }
            Optional<Machine> machineOpt = machineService.findByUserAndHwid(session.getUser(), hwid);
            if (machineOpt.isEmpty()) {
                machine = machineService.registerMachine(session.getUser(), hwid, "Loader", "Windows", null, null, null, null, null, null);
            } else {
                machine = machineOpt.get();
                if (machine.getRevokedAt() != null) {
                    sendAuthError(session, ServerErrorCode.MACHINE_REVOKED.getCode(), ServerErrorCode.MACHINE_REVOKED.getInternalDescription());
                    return;
                }
                machineService.updateLastSeen(machine);
            }
        } else {
            // Erreur: ni machine ni download dans la session
            log.error("Invalid session state: neither machine nor download found for {}", session.getRemoteAddress());
            sendAuthError(session, ServerErrorCode.INVALID_STATE.getCode(), ServerErrorCode.INVALID_STATE.getInternalDescription());
            return;
        }

        if (sessionService.hasActiveSessionForMachine(machine)) {
            log.warn("Multi-instance detected for machine {} (user: {})", machine.getHwid(), session.getUser().getUsername());
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            fields.put("User", session.getUser().getUsername());
            fields.put("HWID", machine.getHwid());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u26A0\uFE0F Multi-Instance Detected", "Already connected from this machine",
                    DiscordWebhookService.COLOR_RED, fields);
            sendAuthError(session, ServerErrorCode.SESSION_ALREADY_EXISTS.getCode(), ServerErrorCode.SESSION_ALREADY_EXISTS.getInternalDescription());
            return;
        }

        if (sessionService.hasReachedSessionLimit(license)) {
            Map<String, String> limitFields = new LinkedHashMap<>();
            limitFields.put("IP", session.getRemoteAddress());
            limitFields.put("User", session.getUser().getUsername());
            limitFields.put("HWID", machine.getHwid());
            if (data.pcName() != null && !data.pcName().isBlank()) limitFields.put("Nom du PC", data.pcName());
            discordWebhook.sendFail("⚠️ Session Limit", "Session limit reached for license",
                    DiscordWebhookService.COLOR_RED, limitFields);
            sendAuthError(session, ServerErrorCode.SESSION_ALREADY_EXISTS.getCode(), ServerErrorCode.SESSION_ALREADY_EXISTS.getInternalDescription());
            return;
        }

        Session dbSession = sessionService.create(
                license, machine,
                session.getIp(), session.getSessionKey()
        );

        byte[] challenge = cryptoService.generateChallenge();
        byte[] userSecret = cryptoService.generateRandomBytes(32);
        session.setUserSecret(userSecret);

        // Phase 1+2+3: capture authSalt + algoSeed + expectedFingerprint at
        // token issuance so ClientAuthHandler can recompute the loader's
        // auth_tag without a DB lookup.
        byte[] authSalt = (session.getDownload() != null) ? session.getDownload().getAuthSalt() : null;
        byte[] algoSeed = (session.getDownload() != null) ? session.getDownload().getAlgoSeed() : null;
        byte[] fingerprint = (session.getDownload() != null) ? session.getDownload().getExpectedFingerprint() : null;
        TemporaryClientToken tempToken = sessionService.createTemporaryClientToken(
                session.getUser(), license, machine, data.productCode(),
                machine.getHwid(), session.getIp(), authSalt, algoSeed, fingerprint
        );

        session.setLicense(license);
        session.setMachine(machine);
        session.setDbSession(dbSession);
        session.setProductCode(data.productCode());
        session.setPendingChallenge(challenge);
        session.setPermissions(PERM_BASIC);
        session.setState(ClientSession.SessionState.AUTHENTICATED);

        session.setFileDownloadSequence(bucketService.discoverDownloadSequence(data.productCode()));

        sendAuthSuccess(session, dbSession.getTokenHash(), PERM_BASIC,
                dbSession.getExpiresAt().getEpochSecond(), challenge, tempToken.getToken(), userSecret,
                tempToken.getClientAttestationToken());

        log.info("Product select success for {} (user: {}, product: {})",
                session.getRemoteAddress(), session.getUser().getUsername(), data.productCode());

        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("Pseudo", session.getUser().getUsername());
        fields.put("UUID", session.getUser().getId().toString());
        fields.put("IP", session.getRemoteAddress());
        fields.put("HWID", machine.getHwid());
        fields.put("Discord", session.getUser().getDiscordId() != null ? "<@" + session.getUser().getDiscordId() + ">" : "N/A");
        fields.put("Produit", license.getProduct().getName());
        fields.put("Expiration", license.getExpiresAt() != null ? license.getExpiresAt().toString() : "Lifetime");
        fields.put("Nom du PC", machine.getPcName() != null ? machine.getPcName() : "N/A");
        fields.put("Executable", data.executablePath() != null ? data.executablePath() : "N/A");
        discordWebhook.sendSuccess("\uD83D\uDECD\uFE0F Product Select", "Product selected successfully",
                DiscordWebhookService.COLOR_GREEN, fields);
    }

    private void sendAuthSuccess(ClientSession session, String token, int permissions, long expiresAt, byte[] challenge, byte[] temporaryClientToken, byte[] userSecret, byte[] clientAttestationToken) {
        byte[] tokenBytes = HexFormat.of().parseHex(token);
        byte[] payload = packetWriter.writeAuthSuccessWithTempTokenAndSecret(tokenBytes, permissions, expiresAt, challenge, temporaryClientToken, userSecret, clientAttestationToken);
        packetSender.sendEncrypted(session, PacketType.AUTH_RESPONSE, payload);
    }

    private void sendAuthError(ClientSession session, int code, String message) {
        byte[] payload = packetWriter.writeAuthError(code, message);
        packetSender.sendEncrypted(session, PacketType.AUTH_RESPONSE, payload);
    }
}