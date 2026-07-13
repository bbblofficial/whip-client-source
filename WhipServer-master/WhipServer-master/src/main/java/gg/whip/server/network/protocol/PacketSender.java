package gg.whip.server.network.protocol;

import gg.whip.server.data.RawPacket;
import gg.whip.server.service.CryptoService;
import gg.whip.server.data.ClientSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PacketSender {

    private final CryptoService cryptoService;

    public void sendEncrypted(ClientSession session, PacketType type, byte[] payload) {
        byte[] nonce = cryptoService.generateNonce();
        byte[] encrypted = cryptoService.encrypt(payload, session.getSendKey(), nonce);
        byte[] hmac = cryptoService.hmac(encrypted, session.getSendKey());
        session.send(new RawPacket(type, nonce, encrypted, hmac));

    }

    public void sendPlain(ClientSession session, PacketType type, byte[] payload) {
        byte[] nonce = new byte[ProtocolConstants.NONCE_SIZE];
        byte[] hmac = new byte[ProtocolConstants.HMAC_SIZE];
        session.send(new RawPacket(type, nonce, payload, hmac));
    }

    public void send(ClientSession session, PacketType type, byte[] payload) {
        if (session.getSendKey() != null) {
            sendEncrypted(session, type, payload);
        } else {
            sendPlain(session, type, payload);
        }
    }
}
