package gg.whip.server.handler.impl;

import fr.whip.api.model.User;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.ConnectFailReportData;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.PacketReader;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketWriter;
import gg.whip.server.repository.DownloadRepository;
import gg.whip.server.repository.MachineRepository;
import gg.whip.server.service.AnomalyDetectionService;
import gg.whip.server.service.AntiReplayService;
import gg.whip.server.service.BlacklistService;
import gg.whip.server.service.CryptoService;
import gg.whip.server.service.DiscordWebhookService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class ConnectFailReportHandler extends AbstractSecureHandler {

    private static final Logger log = LoggerFactory.getLogger(ConnectFailReportHandler.class);

    private final CryptoService cryptoService;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final BlacklistService blacklistService;
    private final DiscordWebhookService discordWebhook;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;
    private final DownloadRepository downloadRepository;
    private final MachineRepository machineRepository;

    @Override protected Logger getLogger() { return log; }
    @Override protected CryptoService getCryptoService() { return cryptoService; }
    @Override protected AntiReplayService getAntiReplayService() { return antiReplayService; }
    @Override protected AnomalyDetectionService getAnomalyDetectionService() { return anomalyDetectionService; }
    @Override protected PacketWriter getPacketWriter() { return packetWriter; }
    @Override protected PacketSender getPacketSender() { return packetSender; }

    @Override
    protected UUID getSessionUuid(ClientSession session) {
        return UUID.nameUUIDFromBytes(session.getTempSessionId().getBytes());
    }

    @Override
    public boolean requiresEncryption() { return true; }

    @Override
    public void handle(ClientSession session, RawPacket packet) {
        super.handle(session, packet);
    }

    @Override
    protected void processDecrypted(ClientSession session, byte[] decrypted) {
        ConnectFailReportData data;
        try {
            data = packetReader.readConnectFailReport(decrypted);
        } catch (Exception e) {
            log.warn("Failed to parse CONNECT_FAIL_REPORT from {}: {}", session.getRemoteAddress(), e.getMessage());
            session.close();
            return;
        }

        boolean isDebugger = session.getBlockReportReason() == null;

        log.info("CONNECT_FAIL_REPORT from {} — type: {}, parent: {}, detection: [{}], downloadId: {}, hwid: {}, shots: {}",
                session.getRemoteAddress(),
                isDebugger ? "DEBUGGER_PRE_AUTH" : session.getBlockReportReason(),
                data.parentProcess(),
                data.detectionTag(),
                data.downloadId(),
                data.hwid(),
                data.screenshots().size());

        // Résoudre le user depuis downloadId ou hwid (pré-auth : pas de session authentifiée)
        User resolvedUser = session.getUser();
        if (resolvedUser == null) {
            resolvedUser = resolveUser(data.downloadId(), data.hwid());
        }

        // Ban uniquement pour debugger détecté (pas pour connect-failed ou autres erreurs réseau)
        boolean isDebuggerReport = isDebugger &&
                ("anti-debug".equals(data.parentProcess()) || "auth-anti-debug".equals(data.parentProcess())
                        || (data.parentProcess() != null && !data.parentProcess().startsWith("connect-failed")));
        boolean banned = false;
        if (isDebuggerReport && resolvedUser != null && !blacklistService.isBlacklisted(resolvedUser)) {
            try {
                String banReason = data.downloadId() != null && !data.downloadId().isBlank()
                        ? "Debugger pré-auth — dl:" + data.downloadId()
                        : "Debugger pré-auth — hwid:" + data.hwid();
                blacklistService.blacklist(resolvedUser, banReason, null, "anti-debug");
                banned = true;
                log.warn("Banned user {} for pre-auth debugger (dl={}, hwid={})",
                        resolvedUser.getUsername(), data.downloadId(), data.hwid());
            } catch (Exception e) {
                log.error("Failed to ban user {} after pre-auth debugger", resolvedUser.getUsername(), e);
            }
        }

        String parent = data.parentProcess() != null ? data.parentProcess() : "";
        boolean hasDetectionTag = data.detectionTag() != null && !data.detectionTag().isBlank();
        String title, description;
        if ("anti-debug".equals(parent) || "auth-anti-debug".equals(parent) || (isDebugger && hasDetectionTag)) {
            title       = "🔍 Debugger détecté (pré-auth)";
            description = hasDetectionTag
                    ? "Debugger détecté durant l'authentification"
                    : ("auth-anti-debug".equals(parent)
                            ? "Debugger détecté durant l'authentification"
                            : "Outil de debug actif avant l'authentification");
        } else if (parent.startsWith("connect-failed") || !isDebugger && parent.isEmpty()) {
            title       = "🌐 Échec de connexion au serveur";
            description = "WhipLoader n'a pas pu se connecter";
        } else if (!isDebugger) {
            title       = "🚫 Connexion bloquée";
            description = "WhipLoader a été rejeté par le serveur";
        } else {
            title       = "⚠️ Rapport de connexion";
            description = "Activité suspecte détectée";
        }

        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("IP", session.getRemoteAddress());
        if (!isDebugger && session.getBlockReportExe() != null && !session.getBlockReportExe().isBlank())
            fields.put("Exe", session.getBlockReportExe());
        if (data.parentProcess() != null && !data.parentProcess().isBlank())
            fields.put("Lancé par", data.parentProcess());
        if (data.downloadId() != null && !data.downloadId().isBlank())
            fields.put("Download ID", data.downloadId());
        if (data.hwid() != null && !data.hwid().isBlank())
            fields.put("HWID", data.hwid());
        if (!isDebugger && session.getBlockReportPcName() != null && !session.getBlockReportPcName().isBlank())
            fields.put("PC", session.getBlockReportPcName());
        if (resolvedUser != null) {
            fields.put("User", resolvedUser.getUsername());
            if (resolvedUser.getDiscordId() != null)
                fields.put("Discord", "<@" + resolvedUser.getDiscordId() + ">");
        } else if (session.getBlockReportUsername() != null && !session.getBlockReportUsername().isBlank()) {
            fields.put("Propriétaire exe", session.getBlockReportUsername());
        }
        if (!isDebugger)
            fields.put("Raison", session.getBlockReportReason());
        if (hasDetectionTag)
            fields.put("Détection", data.detectionTag());
        if (isDebuggerReport)
            fields.put("Sanction", banned ? "🔨 Banni (permanent)" : resolvedUser != null ? "Déjà banni" : "Inconnu (pas d'identifiant)");

        discordWebhook.sendReverse(
                title, description,
                DiscordWebhookService.COLOR_RED,
                fields,
                data.screenshots().isEmpty() ? Collections.emptyList() : data.screenshots()
        );

        session.close();
    }

    private User resolveUser(String downloadId, String hwid) {
        if (downloadId != null && !downloadId.isBlank()) {
            User u = downloadRepository.findByDownloadIdWithUser(downloadId)
                    .map(d -> d.getUser()).orElse(null);
            if (u != null) return u;
        }
        if (hwid != null && !hwid.isBlank()) {
            // Non-revoked first; fall back to any machine (including revoked)
            return machineRepository.findByHwidNotRevokedWithUser(hwid)
                    .map(m -> m.getUser())
                    .orElseGet(() -> machineRepository.findByHwidWithUser(hwid)
                            .stream().findFirst().map(m -> m.getUser()).orElse(null));
        }
        return null;
    }
}
