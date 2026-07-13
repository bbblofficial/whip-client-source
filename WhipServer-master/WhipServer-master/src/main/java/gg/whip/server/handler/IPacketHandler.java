package gg.whip.server.handler;

import gg.whip.server.data.ClientSession;
import gg.whip.server.data.RawPacket;

public interface IPacketHandler {

    void handle(ClientSession session, RawPacket packet);

    default boolean requiresEncryption() {
        return true;
    }
}
