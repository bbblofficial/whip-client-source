package gg.whip.server.handler.impl;

import gg.whip.server.data.ClientSession;
import gg.whip.server.data.RawPacket;
import gg.whip.server.data.ReverseDetectedScreenshotsData;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.PacketReader;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketWriter;
import gg.whip.server.service.AnomalyDetectionService;
import gg.whip.server.service.AntiReplayService;
import gg.whip.server.service.CryptoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class ReverseDetectedScreenshotsHandler extends AbstractSecureHandler {

    private final CryptoService cryptoService;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;
    private final ReverseDetectedHandler reverseDetectedHandler;

    @Override protected org.slf4j.Logger getLogger() { return log; }
    @Override protected CryptoService getCryptoService() { return cryptoService; }
    @Override protected AntiReplayService getAntiReplayService() { return antiReplayService; }
    @Override protected AnomalyDetectionService getAnomalyDetectionService() { return anomalyDetectionService; }
    @Override protected PacketWriter getPacketWriter() { return packetWriter; }
    @Override protected PacketSender getPacketSender() { return packetSender; }

    @Override
    protected UUID getSessionUuid(ClientSession session) {
        return session.getDbSession() != null ? session.getDbSession().getId() : null;
    }

    @Override
    public boolean requiresEncryption() { return true; }

    @Override
    public void handle(ClientSession session, RawPacket packet) {
        super.handle(session, packet);
    }

    @Override
    protected void processDecrypted(ClientSession session, byte[] decrypted) {
        ReverseDetectedScreenshotsData data;
        try {
            data = packetReader.readReverseDetectedScreenshots(decrypted);
        } catch (Exception e) {
            log.warn("Failed to parse REVERSE_DETECTED_SCREENSHOTS from {}: {}", session.getRemoteAddress(), e.getMessage());
            session.close();
            return;
        }

        ReverseDetectedHandler.PendingReport pending = ReverseDetectedHandler.removePending(data.requestId());
        if (pending == null) {
            log.warn("No pending report for requestId {} from {}", data.requestId(), session.getRemoteAddress());
            session.close();
            return;
        }

        pending.timeout().cancel(false);

        log.debug("Screenshots received for requestId {} ({} images)", data.requestId(), data.screenshots().size());
        if (pending.isVsEnv()) {
            reverseDetectedHandler.sendVsEnvWebhook(
                    pending.session(), pending.data(), pending.layerDetail(), data.screenshots());
        } else {
            reverseDetectedHandler.sendReverseWebhook(
                    pending.session(), pending.data(), pending.banned(),
                    pending.isSoft(), pending.layerDetail(), data.screenshots());
        }
        pending.session().close();
    }

    @Override
    protected void onNonceReplay(ClientSession session) { session.close(); }

    @Override
    protected void onHmacFailed(ClientSession session) { session.close(); }

    @Override
    protected void onDecryptionFailed(ClientSession session) { session.close(); }
}
