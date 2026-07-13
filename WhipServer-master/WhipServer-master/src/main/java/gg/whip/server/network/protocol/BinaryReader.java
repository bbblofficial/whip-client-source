package gg.whip.server.network.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;

public class BinaryReader implements AutoCloseable {

    private static final int MAX_STRING_LENGTH = 32767;

    private final ByteBuf buf;

    private BinaryReader(byte[] data) {
        this.buf = Unpooled.wrappedBuffer(data);
    }

    public static <T> T read(byte[] data, Function<BinaryReader, T> reader) {
        try (BinaryReader r = new BinaryReader(data)) {
            return reader.apply(r);
        }
    }

    public int readInt() {
        return buf.readInt();
    }

    public long readLong() {
        return buf.readLong();
    }

    public short readShort() {
        return buf.readShort();
    }

    public boolean readBoolean() {
        return buf.readBoolean();
    }

    public byte[] readFixedBytes(int length) {
        byte[] bytes = new byte[length];
        buf.readBytes(bytes);
        return bytes;
    }

    public byte[] readBytes() {
        int length = buf.readInt();
        if (length < 0) return null;
        byte[] bytes = new byte[length];
        buf.readBytes(bytes);
        return bytes;
    }

    public String readString() {
        short length = buf.readShort();
        if (length < 0) return null;
        if (length > MAX_STRING_LENGTH) throw new IllegalArgumentException("String too long");
        byte[] bytes = new byte[length];
        buf.readBytes(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public boolean hasRemaining() {
        return buf.isReadable();
    }

    public int remaining() {
        return buf.readableBytes();
    }

    @Override
    public void close() {
        buf.release();
    }
}
