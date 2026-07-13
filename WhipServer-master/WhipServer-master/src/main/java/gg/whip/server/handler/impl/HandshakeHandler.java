package gg.whip.server.handler.impl;

import gg.whip.server.data.ClientHelloData;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.IPacketHandler;
import gg.whip.server.network.protocol.PacketReader;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketType;
import gg.whip.server.network.protocol.PacketWriter;
import gg.whip.server.network.protocol.ProtocolConstants;
import gg.whip.server.service.AnomalyDetectionService;
import gg.whip.server.service.CryptoService;
import gg.whip.server.service.ServerCertificateService;
import gg.whip.server.service.ViolationType;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.KeyPair;

@Component
@RequiredArgsConstructor
public class HandshakeHandler implements IPacketHandler {

    private static final Logger log = LoggerFactory.getLogger(HandshakeHandler.class);

    private final CryptoService cryptoService;
    private final ServerCertificateService certificateService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;

    @Override
    public boolean requiresEncryption() {
        return false;
    }

    @Override
    public void handle(ClientSession session, RawPacket packet) {
        if (session.getState() != ClientSession.SessionState.CONNECTED) {
            log.warn("CLIENT_HELLO in wrong state from {}", session.getRemoteAddress());
            session.close();
            return;
        }

        ClientHelloData data = packetReader.readClientHello(packet.payload());

        if (data.version() != ProtocolConstants.VERSION) {
            log.info("Protocol version mismatch from {}: {}", session.getRemoteAddress(), data.version());
            sendError(session, 1, "Protocol version mismatch");
            session.close();
            return;
        }

        // SECURITY: Validate key and nonce lengths to prevent malformed packets
        if (data.publicKey() == null || data.publicKey().length != 91) {
            log.warn("Invalid client public key length from {}: {} (expected 91)",
                    session.getRemoteAddress(), data.publicKey() != null ? data.publicKey().length : 0);
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.INVALID_PACKET);
            session.close();
            return;
        }

        if (data.nonce() == null || data.nonce().length != 32) {
            log.warn("Invalid client nonce length from {}: {} (expected 32)",
                    session.getRemoteAddress(), data.nonce() != null ? data.nonce().length : 0);
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.INVALID_PACKET);
            session.close();
            return;
        }

        KeyPair serverKeyPair = cryptoService.generateEphemeralKeyPair();
        byte[] serverNonce = cryptoService.generateChallenge();
        String tempSessionId = cryptoService.generateTempSessionId();
        byte[] sessionKey = cryptoService.deriveSessionKey(
                serverKeyPair.getPrivate(),
                data.publicKey(),
                data.nonce(),      // clientNonce
                serverNonce        // serverNonce
        );

        session.setClientNonce(data.nonce());
        session.setClientPublicKey(data.publicKey());
        session.setServerNonce(serverNonce);
        session.setServerKeyPair(serverKeyPair);
        session.setTempSessionId(tempSessionId);
        session.setSessionKey(sessionKey);
        session.setState(ClientSession.SessionState.HELLO_DONE);

        // CERTIFICATE PINNING: Signer la clé publique éphémère avec la clé permanente
        byte[] serverPublicKey = serverKeyPair.getPublic().getEncoded();
        byte[] serverPermanentPublicKey = certificateService.getPublicKeyEncoded();
        byte[] signature = certificateService.signData(serverPublicKey);

        byte[] payload = packetWriter.writeServerHello(
                serverNonce,
                tempSessionId,
                serverPublicKey,
                serverPermanentPublicKey,
                signature
        );
        packetSender.sendPlain(session, PacketType.SERVER_HELLO, payload);

        log.debug("Handshake completed with HKDF for {}, tempSessionId: {}, certificate pinning enabled",
                session.getRemoteAddress(), tempSessionId);
    }

    private void sendError(ClientSession session, int code, String message) {
        byte[] payload = packetWriter.writeError(code, message);
        packetSender.sendPlain(session, PacketType.ERROR, payload);
    }
}
