package gg.whip.server.data;

import gg.whip.server.network.protocol.PacketType;

public record RawPacket(
        PacketType type,
        byte[] nonce,
        byte[] payload,
        byte[] hmac
) {}
