package gg.whip.server.network.codec;

import gg.whip.server.network.protocol.PacketType;
import gg.whip.server.network.protocol.ProtocolConstants;
import gg.whip.server.data.RawPacket;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

public class PacketDecoder extends ByteToMessageDecoder {

    private static final Logger log = LoggerFactory.getLogger(PacketDecoder.class);

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        if (in.readableBytes() < ProtocolConstants.HEADER_SIZE) {
            return;
        }

        in.markReaderIndex();

        byte[] magic = new byte[4];
        in.readBytes(magic);
        if (!Arrays.equals(magic, ProtocolConstants.MAGIC)) {
            log.warn("Invalid magic bytes");
            ctx.close();
            return;
        }

        short version = in.readShort();
        if (version != ProtocolConstants.VERSION) {
            log.warn("Protocol version mismatch: {}", version);
            ctx.close();
            return;
        }

        short typeId = in.readShort();
        int payloadLength = in.readInt();

        if (payloadLength < 0 || payloadLength > ProtocolConstants.MAX_PACKET_SIZE) {
            log.warn("Invalid payload length: {}", payloadLength);
            ctx.close();
            return;
        }

        int totalRemaining = ProtocolConstants.NONCE_SIZE + payloadLength + ProtocolConstants.HMAC_SIZE;
        if (in.readableBytes() < totalRemaining) {
            in.resetReaderIndex();
            return;
        }

        byte[] nonce = new byte[ProtocolConstants.NONCE_SIZE];
        in.readBytes(nonce);

        byte[] payload = new byte[payloadLength];
        in.readBytes(payload);

        byte[] hmac = new byte[ProtocolConstants.HMAC_SIZE];
        in.readBytes(hmac);

        PacketType type = PacketType.fromId(typeId);
        if (type == null) {
            log.warn("Unknown packet type: {}", typeId);
            return;
        }

        RawPacket rawPacket = new RawPacket(type, nonce, payload, hmac);
        out.add(rawPacket);
    }
}