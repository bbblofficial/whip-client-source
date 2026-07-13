package gg.whip.server.handler.impl;

import fr.whip.api.model.Machine;
import fr.whip.api.model.Session;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.MachineInfoData;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.*;
import gg.whip.server.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class MachineInfoHandler extends AbstractSecureHandler {

    private final CryptoService cryptoService;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final MachineService machineService;
    private final DiscordWebhookService discordWebhook;
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
            log.warn("Machine info from unauthenticated session {}", clientSession.getRemoteAddress());
            clientSession.close();
            return;
        }

        super.handle(clientSession, packet);
    }

    @Override
    protected void processDecrypted(ClientSession clientSession, byte[] decrypted) {
        try {
            MachineInfoData data = packetReader.readMachineInfo(decrypted);
            log.info("Machine info from {}: mcUsername='{}', pcName='{}'",
                clientSession.getRemoteAddress(), data.mcUsername(), data.pcName());

            if (!antiReplayService.isTimestampValid(data.timestamp())) {
                log.warn("Invalid timestamp from {}", clientSession.getRemoteAddress());
                anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.INVALID_TIMESTAMP);
                sendResponse(clientSession, false);
                return;
            }

            if (!validateAuthToken(clientSession, data.requestId(), data.authHmac(),
                    data.timestamp(), (short) 0x18)) {
                sendResponse(clientSession, false);
                clientSession.close();
                return;
            }

            Session session = clientSession.getDbSession();
            if (session == null || !session.isActive()) {
                log.warn("Session expired from {}", clientSession.getRemoteAddress());
                sendResponse(clientSession, false);
                return;
            }

            // Store MC username in-memory (for webhooks)
            if (data.mcUsername() != null && !data.mcUsername().isBlank()) {
                clientSession.setMcUsername(data.mcUsername());
            }

            // Update machine pcName if provided
            Machine machine = clientSession.getMachine();
            if (machine != null && data.pcName() != null && !data.pcName().isBlank()) {
                machine.setPcName(data.pcName());
                machineService.updateLastSeen(machine);
            }

            // Send Discord webhook with full info
            sendMachineInfoWebhook(clientSession, data);

            sendResponse(clientSession, true);
            log.info("Machine info processed for {}", clientSession.getRemoteAddress());

        } catch (Exception e) {
            log.error("Error processing machine info from {}", clientSession.getRemoteAddress(), e);
            sendResponse(clientSession, false);
        }
    }

    private void sendResponse(ClientSession session, boolean success) {
        byte[] payload = packetWriter.writeMachineInfoResponse(success);
        packetSender.sendEncrypted(session, PacketType.MACHINE_INFO_RESPONSE, payload);
    }

    private void sendMachineInfoWebhook(ClientSession clientSession, MachineInfoData data) {
        Map<String, String> fields = new LinkedHashMap<>();

        if (clientSession.getUser() != null) {
            fields.put("Pseudo", clientSession.getUser().getUsername());
            fields.put("UUID", clientSession.getUser().getId().toString());
        }

        if (data.mcUsername() != null && !data.mcUsername().isBlank()) {
            fields.put("MC Username", data.mcUsername());
        }

        fields.put("IP", clientSession.getRemoteAddress());

        if (clientSession.getMachine() != null) {
            fields.put("HWID", clientSession.getMachine().getHwid());
            if (data.pcName() != null && !data.pcName().isBlank()) {
                fields.put("Nom du PC", data.pcName());
            }
        }

        // Note: executablePath is not available in MachineInfoData (DLL request)

        if (clientSession.getUser() != null && clientSession.getUser().getDiscordId() != null) {
            fields.put("Discord", "<@" + clientSession.getUser().getDiscordId() + ">");
        }

        if (clientSession.getLicense() != null) {
            fields.put("Produit", clientSession.getLicense().getProduct().getName());
            fields.put("Expiration", clientSession.getLicense().getExpiresAt() != null
                    ? clientSession.getLicense().getExpiresAt().toString() : "Lifetime");
        }

        // Build Minecraft avatar URL if mcUsername is present
        String thumbnailUrl = null;
        if (data.mcUsername() != null && !data.mcUsername().isBlank()) {
            thumbnailUrl = "https://mc-heads.net/avatar/" + data.mcUsername() + "/100.png";
        }

        discordWebhook.sendSuccess("\uD83C\uDFAE Machine Info", "Client machine info received",
                DiscordWebhookService.COLOR_GREEN, fields, thumbnailUrl);
    }

    @Override
    protected void onNonceReplay(ClientSession session) {
        log.warn("Nonce replay detected from {}", session.getRemoteAddress());
        sendResponse(session, false);
        session.getChannel().close();
    }

    @Override
    protected void onHmacFailed(ClientSession session) {
        log.warn("HMAC verification failed from {}", session.getRemoteAddress());
        sendResponse(session, false);
        session.getChannel().close();
    }

    @Override
    protected void onDecryptionFailed(ClientSession session) {
        log.warn("Decryption failed from {}", session.getRemoteAddress());
        sendResponse(session, false);
        session.getChannel().close();
    }
}
