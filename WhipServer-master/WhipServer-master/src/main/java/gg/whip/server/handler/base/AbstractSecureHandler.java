package gg.whip.server.handler.base;

import gg.whip.server.data.ClientSession;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.IPacketHandler;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketType;
import gg.whip.server.network.protocol.PacketWriter;
import gg.whip.server.service.AnomalyDetectionService;
import gg.whip.server.service.AntiReplayService;
import gg.whip.server.service.CryptoService;
import gg.whip.server.service.ViolationType;
import org.slf4j.Logger;

import java.util.UUID;

public abstract class AbstractSecureHandler implements IPacketHandler {

    protected abstract Logger getLogger();
    protected abstract CryptoService getCryptoService();
    protected abstract AntiReplayService getAntiReplayService();
    protected abstract AnomalyDetectionService getAnomalyDetectionService();
    protected abstract PacketWriter getPacketWriter();
    protected abstract PacketSender getPacketSender();

    protected abstract UUID getSessionUuid(ClientSession session);

    protected abstract void processDecrypted(ClientSession session, byte[] decrypted);

    @Override
    public void handle(ClientSession session, RawPacket packet) {
        UUID sessionUuid = getSessionUuid(session);

        if (!getAntiReplayService().checkAndMarkNonce(packet.nonce(), sessionUuid)) {
            getLogger().warn("Nonce replay from {}", session.getRemoteAddress());
            getAnomalyDetectionService().recordViolation(session.getIp(), ViolationType.NONCE_REPLAY);
            onNonceReplay(session);
            return;
        }

        if (!getCryptoService().verifyHmac(packet.payload(), session.getRecvKey(), packet.hmac())) {
            getLogger().warn("HMAC verification failed from {}", session.getRemoteAddress());
            getAnomalyDetectionService().recordViolation(session.getIp(), ViolationType.HMAC_FAILED);
            onHmacFailed(session);
            return;
        }

        byte[] decrypted;
        try {
            decrypted = getCryptoService().decrypt(packet.payload(), session.getRecvKey(), packet.nonce());
        } catch (Exception e) {
            getLogger().warn("Decryption failed from {}", session.getRemoteAddress());
            getAnomalyDetectionService().recordViolation(session.getIp(), ViolationType.DECRYPTION_FAILED);
            onDecryptionFailed(session);
            return;
        }

        processDecrypted(session, decrypted);
    }

    protected boolean validateAuthToken(ClientSession session, String requestId, byte[] authHmac, long timestamp, short packetTypeId) {
        byte[] userSecret = session.getUserSecret();
        if (userSecret == null) {
            getLogger().warn("Missing user secret for {}", session.getRemoteAddress());
            return false;
        }

        if (requestId == null || authHmac == null) {
            getLogger().warn("Missing auth token fields from {}", session.getRemoteAddress());
            return false;
        }

        UUID reqUuid;
        try {
            if (requestId.contains("-")) {
                reqUuid = UUID.fromString(requestId);
            } else {
                long msb = Long.parseUnsignedLong(requestId.substring(0, 16), 16);
                long lsb = Long.parseUnsignedLong(requestId.substring(16, 32), 16);
                reqUuid = new UUID(msb, lsb);
            }
        } catch (Exception e) {
            getLogger().warn("Invalid requestId from {}", session.getRemoteAddress());
            return false;
        }

        if (!getAntiReplayService().isTimestampValid(timestamp)) {
            getLogger().warn("Timestamp outside ±30s window from {}", session.getRemoteAddress());
            getAnomalyDetectionService().recordViolation(session.getIp(), ViolationType.INVALID_TIMESTAMP);
            return false;
        }

        UUID sessionId = getSessionUuid(session);
        if (!getAntiReplayService().checkAndMarkRequestId(reqUuid, sessionId)) {
            getLogger().warn("Request ID replay detected from {}", session.getRemoteAddress());
            getAnomalyDetectionService().recordViolation(session.getIp(), ViolationType.REQUEST_REPLAY);
            return false;
        }

        if (!getCryptoService().verifyAuthHmac(userSecret, packetTypeId, requestId, timestamp, authHmac)) {
            getLogger().warn("Auth HMAC verification failed from {}", session.getRemoteAddress());
            getAnomalyDetectionService().recordViolation(session.getIp(), ViolationType.HMAC_FAILED);
            return false;
        }

        return true;
    }

    protected void onNonceReplay(ClientSession session) {
        sendError(session, 3, "Nonce replay");
    }

    protected void onHmacFailed(ClientSession session) {
        sendError(session, 4, "Invalid signature");
    }

    protected void onDecryptionFailed(ClientSession session) {
        sendError(session, 5, "Decryption failed");
    }

    protected void sendError(ClientSession session, int code, String message) {
        byte[] payload = getPacketWriter().writeError(code, message);
        getPacketSender().send(session, PacketType.ERROR, payload);
    }
}
