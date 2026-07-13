package gg.whip.server.network.codec;

import gg.whip.server.network.protocol.ProtocolConstants;
import gg.whip.server.data.RawPacket;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

public class PacketEncoder extends MessageToByteEncoder<RawPacket> {

    @Override
    protected void encode(ChannelHandlerContext ctx, RawPacket packet, ByteBuf out) {
        out.writeBytes(ProtocolConstants.MAGIC);
        out.writeShort(ProtocolConstants.VERSION);
        out.writeShort(packet.type().getId());
        out.writeInt(packet.payload().length);
        out.writeBytes(packet.nonce());
        out.writeBytes(packet.payload());
        out.writeBytes(packet.hmac());
    }
}
