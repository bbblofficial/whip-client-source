package gg.whip.server.handler.impl;

import fr.whip.api.model.*;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.InitRequestData;
import gg.whip.server.data.ProductInfo;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.PacketReader;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketType;
import gg.whip.server.network.protocol.PacketWriter;
import gg.whip.server.model.MachineHistory;
import gg.whip.server.repository.DownloadRepository;
import gg.whip.server.repository.MachineHistoryRepository;
import gg.whip.server.repository.MachineRepository;
import gg.whip.server.service.AnomalyDetectionService;
import gg.whip.server.service.AntiReplayService;
import gg.whip.server.service.AuthTagValidator;
import gg.whip.server.service.BlacklistService;
import gg.whip.server.service.CryptoService;
import gg.whip.server.service.DiscordWebhookService;
import gg.whip.server.service.LicenseService;
import gg.whip.server.service.ServerErrorCode;
import gg.whip.server.service.SessionService;
import gg.whip.server.service.ViolationType;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Component
@RequiredArgsConstructor
public class InitHandler extends AbstractSecureHandler {

    private static final Logger log = LoggerFactory.getLogger(InitHandler.class);

    private final CryptoService cryptoService;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final DownloadRepository downloadRepository;
    private final MachineRepository machineRepository;
    private final MachineHistoryRepository machineHistoryRepository;
    private final LicenseService licenseService;
    private final SessionService sessionService;
    private final BlacklistService blacklistService;
    private final DiscordWebhookService discordWebhook;
    private final AuthTagValidator authTagValidator;

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
            log.warn("INIT_REQUEST in wrong state from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.INVALID_STATE);

            // Auto-blacklist if user is known — INVALID_STATE after auth is highly suspicious
            if (session.getUser() != null && !blacklistService.isBlacklisted(session.getUser())) {
                blacklistService.blacklist(session.getUser(),
                        "INVALID_STATE after auth from " + session.getIp(),
                        null, "system");
                log.error("Auto-blacklisted user {} — INVALID_STATE after auth", session.getUser().getUsername());
            }

            sendError(session, ServerErrorCode.INVALID_STATE.getCode(), ServerErrorCode.INVALID_STATE.getInternalDescription());
            session.close();
            return;
        }

        super.handle(session, packet);
    }

    @Override
    @Transactional
    protected void processDecrypted(ClientSession session, byte[] decrypted) {
        InitRequestData data = packetReader.readInitRequest(decrypted);

        // SECURITY: Validate timestamp (nonce replay already checked in AbstractSecureHandler)
        if (!antiReplayService.isTimestampValid(data.timestamp())) {
            log.warn("Invalid timestamp from {}", session.getRemoteAddress());
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.INVALID_TIMESTAMP);
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("IP", session.getRemoteAddress());
            if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
            if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
            discordWebhook.sendFail("\u23F0 Timestamp Fail", "Invalid timestamp on INIT_REQUEST",
                    DiscordWebhookService.COLOR_RED, fields);
            sendInitErrorReported(session, ServerErrorCode.INVALID_TIMESTAMP.getCode(), ServerErrorCode.INVALID_TIMESTAMP.getInternalDescription(), data, "Timestamp invalide");
            return;
        }

        User user;
        Download download = null;
        Machine machine = null;

        if (data.useHwid()) {
            Optional<Machine> machineOpt = machineRepository.findByHwidAndRevokedAtIsNull(data.identifier());
            if (machineOpt.isEmpty()) {
                log.warn("Unregistered HWID {} from {}", data.identifier(), session.getRemoteAddress());
                anomalyDetectionService.recordViolation(session.getIp(), ViolationType.AUTH_FAILED);
                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("IP", session.getRemoteAddress());
                fields.put("HWID", data.identifier());
                if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
                if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
                discordWebhook.sendFail("\u274C Init Failed", "Unregistered HWID",
                        DiscordWebhookService.COLOR_RED, fields);
                sendInitErrorReported(session, ServerErrorCode.INVALID_CREDENTIALS.getCode(), ServerErrorCode.INVALID_CREDENTIALS.getInternalDescription(), data, "HWID non enregistr\u00E9");
                return;
            }

            machine = machineOpt.get();
            user = machine.getUser();

            // HWID auth bypasses the loader chain (and the auth_tag/attestation
            // token). Only allowed for admin/owner — devs use this for testing
            // without the full loader pipeline. The WHIP_BYPASS license escape
            // has been removed.
            if (!user.getGrade().isAtLeast(UserGrade.admin)) {
                log.warn("Non-admin user {} (grade: {}) attempted HWID auth from {}",
                        user.getUsername(), user.getGrade(), session.getRemoteAddress());
                anomalyDetectionService.recordViolation(session.getIp(), ViolationType.AUTH_FAILED);
                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("IP", session.getRemoteAddress());
                fields.put("User", user.getUsername());
                fields.put("Grade", user.getGrade().name());
                fields.put("HWID", data.identifier());
                if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
                if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
                discordWebhook.sendFail("🚫 Unauthorized HWID Auth", "Non-admin user attempted HWID authentication",
                        DiscordWebhookService.COLOR_RED, fields);
                sendInitErrorReported(session, ServerErrorCode.INSUFFICIENT_PERMISSIONS.getCode(), ServerErrorCode.INSUFFICIENT_PERMISSIONS.getInternalDescription(), data, "Auth HWID non-admin refusée");
                return;
            }

            if (blacklistService.isBlacklisted(user)) {
                log.warn("Blacklisted user {} attempted HWID auth from {}", user.getUsername(), session.getRemoteAddress());
                anomalyDetectionService.recordViolation(session.getIp(), ViolationType.AUTH_FAILED);
                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("IP", session.getRemoteAddress());
                fields.put("User", user.getUsername());
                fields.put("HWID", data.identifier());
                discordWebhook.sendFail("🚫 Blacklisted User", "Blacklisted user attempted HWID authentication",
                        DiscordWebhookService.COLOR_RED, fields);
                sendInitErrorReported(session, ServerErrorCode.ACCOUNT_BLACKLISTED.getCode(), ServerErrorCode.ACCOUNT_BLACKLISTED.getInternalDescription(), data, "Utilisateur blacklisté (HWID)");
                return;
            }

            log.debug("Auth via HWID for admin user {} from {}", user.getUsername(), session.getRemoteAddress());
        } else {
            Optional<Download> downloadOpt = downloadRepository.findByDownloadId(data.identifier());
            if (downloadOpt.isEmpty()) {
                log.warn("Invalid download ID {} from {}", data.identifier(), session.getRemoteAddress());
                anomalyDetectionService.recordViolation(session.getIp(), ViolationType.AUTH_FAILED);
                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("IP", session.getRemoteAddress());
                fields.put("Download ID", data.identifier());
                if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
                if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
                discordWebhook.sendFail("\u274C Init Failed", "Invalid download ID",
                        DiscordWebhookService.COLOR_RED, fields);
                sendInitError(session, ServerErrorCode.INVALID_CREDENTIALS.getCode(), ServerErrorCode.INVALID_CREDENTIALS.getInternalDescription());
                return;
            }

            download = downloadOpt.get();

            if (download.isRevoked()) {
                log.warn("Revoked download ID {} from {}", data.identifier(), session.getRemoteAddress());
                anomalyDetectionService.recordViolation(session.getIp(), ViolationType.AUTH_FAILED);
                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("IP", session.getRemoteAddress());
                fields.put("Download ID", data.identifier());
                if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
                if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
                discordWebhook.sendFail("\u274C Init Failed", "Revoked download ID",
                        DiscordWebhookService.COLOR_RED, fields);
                String revokeReason = download.getRevokeReason();
                if (revokeReason != null && !revokeReason.isBlank()) {
                    sendInitErrorReportedWithReason(session, ServerErrorCode.REVOKED_DOWNLOAD.getCode(), revokeReason, data, "Download ID révoqué");
                } else {
                    sendInitErrorReported(session, ServerErrorCode.REVOKED_DOWNLOAD.getCode(), ServerErrorCode.REVOKED_DOWNLOAD.getInternalDescription(), data, "Download ID révoqué");
                }
                return;
            }

            user = download.getUser();

            if (blacklistService.isBlacklisted(user)) {
                log.warn("Blacklisted user {} attempted download auth from {}", user.getUsername(), session.getRemoteAddress());
                anomalyDetectionService.recordViolation(session.getIp(), ViolationType.AUTH_FAILED);
                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("IP", session.getRemoteAddress());
                fields.put("User", user.getUsername());
                fields.put("Download ID", data.identifier());
                if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
                if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
                discordWebhook.sendFail("🚫 Blacklisted User", "Blacklisted user attempted download authentication",
                        DiscordWebhookService.COLOR_RED, fields);
                sendInitErrorReported(session, ServerErrorCode.ACCOUNT_BLACKLISTED.getCode(), ServerErrorCode.ACCOUNT_BLACKLISTED.getInternalDescription(), data, "Utilisateur blacklisté (Download)");
                return;
            }

            // SECURITY: HWID verification for download authentication
            List<Machine> userMachines = machineRepository.findByUserAndRevokedAtIsNull(user);

            if (userMachines.isEmpty()) {
                // First connection - register this HWID as a new machine
                machine = new Machine();
                machine.setUser(user);
                machine.setHwid(data.hwid());
                machine.setPcName(data.pcName());
                machine.setOs(data.os());
                machine.setGpuName(blankToNull(data.gpuName()));
                machine.setCpuBrand(blankToNull(data.cpuBrand()));
                machine.setRamHex(blankToNull(data.ramHex()));
                machine.setBoardModel(blankToNull(data.boardModel()));
                machine.setScreenInfo(blankToNull(data.screenInfo()));
                machine.setStorageInfo(blankToNull(data.storageInfo()));
                machineRepository.save(machine);

                log.info("Registered new machine for user {} with HWID {} from {}",
                        user.getUsername(), data.hwid(), session.getRemoteAddress());

                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("User", user.getUsername());
                fields.put("HWID", data.hwid());
                fields.put("IP", session.getRemoteAddress());
                if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
                discordWebhook.sendSuccess("🆕 New Machine", "First connection - machine registered",
                        DiscordWebhookService.COLOR_GREEN, fields);
            } else {
                // User has existing machines - verify HWID matches one of them
                Optional<Machine> machineOpt = userMachines.stream()
                        .filter(m -> m.getHwid().equals(data.hwid()))
                        .findFirst();

                if (machineOpt.isEmpty()) {
                    log.warn("Download auth with unregistered HWID {} for user {} from {}",
                            data.hwid(), user.getUsername(), session.getRemoteAddress());
                    anomalyDetectionService.recordViolation(session.getIp(), ViolationType.HWID_MISMATCH);
                    Map<String, String> fields = new LinkedHashMap<>();
                    fields.put("IP", session.getRemoteAddress());
                    fields.put("User", user.getUsername());
                    fields.put("Download ID", data.identifier());
                    fields.put("HWID Provided", data.hwid());
                    fields.put("Registered HWIDs", String.valueOf(userMachines.size()));
                    if (data.pcName() != null && !data.pcName().isBlank()) fields.put("Nom du PC", data.pcName());
                    if (data.executablePath() != null && !data.executablePath().isBlank()) fields.put("Executable", data.executablePath());
                    discordWebhook.sendFail("🚨 HWID Mismatch", "Download auth with unregistered HWID",
                            DiscordWebhookService.COLOR_RED, fields);
                    session.setBlockReportUsername(user.getUsername()); // propriétaire du download
                    sendInitErrorReported(session, ServerErrorCode.HWID_MISMATCH.getCode(), ServerErrorCode.HWID_MISMATCH.getInternalDescription(), data, "HWID Mismatch — exe de " + user.getUsername());
                    return;
                }

                machine = machineOpt.get();

                // Update machine fields and log any changes to history
                List<MachineHistory> historyEntries = new ArrayList<>();
                UUID machineId = machine.getId();

                if (data.pcName() != null && !data.pcName().equals(machine.getPcName())) {
                    historyEntries.add(new MachineHistory(machineId, "pc_name", machine.getPcName(), data.pcName()));
                    machine.setPcName(data.pcName());
                }
                if (data.os() != null && !data.os().equals(machine.getOs())) {
                    historyEntries.add(new MachineHistory(machineId, "os", machine.getOs(), data.os()));
                    machine.setOs(data.os());
                }
                String gpuName = blankToNull(data.gpuName());
                if (gpuName != null && !gpuName.equals(machine.getGpuName())) {
                    historyEntries.add(new MachineHistory(machineId, "gpu_name", machine.getGpuName(), gpuName));
                    machine.setGpuName(gpuName);
                }
                String cpuBrand = blankToNull(data.cpuBrand());
                if (cpuBrand != null && !cpuBrand.equals(machine.getCpuBrand())) {
                    historyEntries.add(new MachineHistory(machineId, "cpu_brand", machine.getCpuBrand(), cpuBrand));
                    machine.setCpuBrand(cpuBrand);
                }
                String ramHex = blankToNull(data.ramHex());
                if (ramHex != null && !ramHex.equals(machine.getRamHex())) {
                    historyEntries.add(new MachineHistory(machineId, "ram_hex", machine.getRamHex(), ramHex));
                    machine.setRamHex(ramHex);
                }
                String boardModel = blankToNull(data.boardModel());
                if (boardModel != null && !boardModel.equals(machine.getBoardModel())) {
                    historyEntries.add(new MachineHistory(machineId, "board_model", machine.getBoardModel(), boardModel));
                    machine.setBoardModel(boardModel);
                }
                String screenInfo = blankToNull(data.screenInfo());
                if (screenInfo != null && !screenInfo.equals(machine.getScreenInfo())) {
                    historyEntries.add(new MachineHistory(machineId, "screen_info", machine.getScreenInfo(), screenInfo));
                    machine.setScreenInfo(screenInfo);
                }
                String storageInfo = blankToNull(data.storageInfo());
                if (storageInfo != null && !storageInfo.equals(machine.getStorageInfo())) {
                    historyEntries.add(new MachineHistory(machineId, "storage_info", machine.getStorageInfo(), storageInfo));
                    machine.setStorageInfo(storageInfo);
                }
                if (!historyEntries.isEmpty()) {
                    machineRepository.save(machine);
                    machineHistoryRepository.saveAll(historyEntries);
                    log.info("Updated machine info for user {} (HWID: {}) - {} field(s) changed",
                            user.getUsername(), data.hwid(), historyEntries.size());
                }

                log.debug("HWID verified for user {} from {}", user.getUsername(), session.getRemoteAddress());
            }

            // Attach user/download to the session BEFORE running the auth_tag
            // check. If the check fails (and the threat threshold is reached),
            // AnomalyDetectionService will iterate channels for this IP and
            // auto-blacklist the matching user — that requires the session to
            // already know who the user is.
            session.setUser(user);
            session.setDownload(download);

            // Phase 1+2+3 auth_tag: HMAC(SHA256(authSalt||algoSeed||codeFingerprint), hwid||score).
            //   - algoSeed: crack non-portable cross-user
            //   - codeFingerprint: any patch in loader .text breaks the HMAC
            if (download.getAuthSalt() != null && download.getAlgoSeed() != null
                    && download.getExpectedFingerprint() != null) {
                AuthTagValidator.MismatchCause cause = authTagValidator.diagnose(
                        download.getAuthSalt(), download.getAlgoSeed(),
                        download.getExpectedFingerprint(),
                        data.hwid().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        data.authTag());

                if (cause != AuthTagValidator.MismatchCause.NONE) {
                    String causeStr = switch (cause) {
                        case FINGERPRINT      -> "FINGERPRINT_MISMATCH (wrong loader binary or ASLR delta on .text)";
                        case SCORE_OR_UNKNOWN -> "SENTINEL_SCORE_NONZERO (anti-debug triggered) or corrupted auth data";
                        default               -> "UNKNOWN";
                    };
                    log.error("EXE TAMPERED — auth_tag mismatch on INIT_REQUEST from {} (user: {}, download: {}, cause: {})",
                            session.getRemoteAddress(), user.getUsername(), data.identifier(), causeStr);
                    anomalyDetectionService.recordViolation(session.getIp(), ViolationType.AUTH_TAG_MISMATCH);
                    Map<String, String> tagFields = new LinkedHashMap<>();
                    tagFields.put("IP", session.getRemoteAddress());
                    tagFields.put("User", user.getUsername());
                    tagFields.put("Discord", user.getDiscordId() != null ? "<@" + user.getDiscordId() + ">" : "N/A");
                    tagFields.put("Download ID", data.identifier());
                    tagFields.put("HWID", data.hwid());
                    if (data.pcName() != null && !data.pcName().isBlank()) tagFields.put("Nom du PC", data.pcName());
                    if (data.executablePath() != null && !data.executablePath().isBlank()) tagFields.put("Executable", data.executablePath());
                    tagFields.put("Cause", causeStr);
                    discordWebhook.sendFail("🚨 EXE TAMPERED",
                            "Loader auth_tag mismatch — " + causeStr,
                            DiscordWebhookService.COLOR_RED, tagFields);
                    sendInitErrorReported(session, ServerErrorCode.INVALID_CREDENTIALS.getCode(),
                            "Anti-debug check failed", data, "EXE modifié / Auth tag invalide");
                    session.close();
                    return;
                }
            }

            download.incrementUseCount();
            downloadRepository.save(download);

            log.debug("Auth via downloadId for user {} from {}", user.getUsername(), session.getRemoteAddress());
        }

        List<License> validLicenses = licenseService.findActiveLicenses(user).stream()
                .filter(License::isValid)
                .toList();

        if (validLicenses.isEmpty()) {
            log.info("No valid licenses for user {} from {}", user.getUsername(), session.getRemoteAddress());
            sendInitErrorReported(session, ServerErrorCode.NO_VALID_LICENSE.getCode(), ServerErrorCode.NO_VALID_LICENSE.getInternalDescription(), data, "Aucune licence valide");
            return;
        }

        List<ProductInfo> products = new ArrayList<>();
        for (License license : validLicenses) {
            long expiresAt = license.getExpiresAt() != null ? license.getExpiresAt().getEpochSecond() : 0;
            boolean lifetime = license.getExpiresAt() == null;

            products.add(new ProductInfo(
                    license.getProduct().getCode(),
                    license.getProduct().getName(),
                    license.getProduct().getDescription(),
                    expiresAt,
                    lifetime
            ));
        }

        // Multi-instance check: reject immediately if this machine already has an active session.
        if (machine != null && sessionService.hasActiveSessionForMachine(machine)) {
            log.warn("Multi-instance detected at INIT for machine {} (user: {})", machine.getHwid(), user.getUsername());
            Map<String, String> miFields = new LinkedHashMap<>();
            miFields.put("IP", session.getRemoteAddress());
            miFields.put("User", user.getUsername());
            miFields.put("HWID", machine.getHwid());
            if (data.pcName() != null && !data.pcName().isBlank()) miFields.put("Nom du PC", data.pcName());
            discordWebhook.sendFail("⚠️ Multi-Instance (INIT)", "Already connected from this machine",
                    DiscordWebhookService.COLOR_RED, miFields);
            sendInitErrorReported(session, ServerErrorCode.SESSION_ALREADY_EXISTS.getCode(),
                    ServerErrorCode.SESSION_ALREADY_EXISTS.getInternalDescription(), data, "Multi-instance détecté");
            return;
        }

        session.setDownload(download);
        session.setMachine(machine);
        session.setUser(user);
        session.setHwid(data.hwid());  // Store real HWID from client
        session.setState(ClientSession.SessionState.INIT_DONE);

        sendInitSuccess(session, user.getUsername(), products);

        log.info("Init success for {} (user: {}, products: {}, method: {})",
                session.getRemoteAddress(), user.getUsername(), products.size(),
                data.useHwid() ? "HWID" : "downloadId");

        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("Pseudo", user.getUsername());
        fields.put("UUID", user.getId().toString());
        fields.put("IP", session.getRemoteAddress());
        fields.put("HWID", data.useHwid() ? data.identifier() : data.hwid());
        fields.put("Discord", user.getDiscordId() != null ? "<@" + user.getDiscordId() + ">" : "N/A");
        fields.put("Produit(s)", products.stream()
                .map(p -> p.name())
                .reduce((a, b) -> a + ", " + b)
                .orElse("N/A"));
        fields.put("Expiration", validLicenses.stream()
                .map(l -> l.getExpiresAt() != null ? l.getExpiresAt().toString() : "Lifetime")
                .reduce((a, b) -> a + ", " + b)
                .orElse("N/A"));
        fields.put("Nom du PC", data.pcName() != null ? data.pcName() : "N/A");
        fields.put("Executable", data.executablePath() != null ? data.executablePath() : "N/A");
        fields.put("Méthode", data.useHwid() ? "HWID" : "Download ID");
        discordWebhook.sendSuccess("\u2705 Init Success", "Client initialized successfully",
                DiscordWebhookService.COLOR_GREEN, fields);
    }

    private void sendInitSuccess(ClientSession session, String username, List<ProductInfo> products) {
        byte[] payload = packetWriter.writeInitSuccess(username, products);
        packetSender.sendEncrypted(session, PacketType.INIT_RESPONSE, payload);
    }

    private void sendInitError(ClientSession session, int code, String message) {
        byte[] payload = packetWriter.writeInitError(code, message);
        packetSender.sendEncrypted(session, PacketType.INIT_RESPONSE, payload);
    }

    // Envoie l'erreur ET stocke la raison pour ConnectFailReportHandler.
    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }

    private void sendInitErrorReported(ClientSession session, int code, String message,
                                        InitRequestData data, String reason) {
        if (session.getBlockReportReason() == null) {
            session.setBlockReportReason(reason);
            session.setBlockReportPcName(data != null ? data.pcName() : null);
            session.setBlockReportExe(data != null ? data.executablePath() : null);
        }
        sendInitError(session, code, message);
    }

    private void sendInitErrorWithReason(ClientSession session, int code, String userReason) {
        byte[] payload = packetWriter.writeInitErrorWithReason(code, userReason);
        packetSender.sendEncrypted(session, PacketType.INIT_RESPONSE, payload);
    }

    private void sendInitErrorReportedWithReason(ClientSession session, int code, String userReason,
                                                  InitRequestData data, String logReason) {
        if (session.getBlockReportReason() == null) {
            session.setBlockReportReason(logReason);
            session.setBlockReportPcName(data != null ? data.pcName() : null);
            session.setBlockReportExe(data != null ? data.executablePath() : null);
        }
        sendInitErrorWithReason(session, code, userReason);
    }
}
