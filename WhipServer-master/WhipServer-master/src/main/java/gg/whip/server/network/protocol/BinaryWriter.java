package gg.whip.server.network.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;

import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

public class BinaryWriter implements AutoCloseable {

    private final ByteBuf buf;

    private BinaryWriter() {
        this.buf = PooledByteBufAllocator.DEFAULT.heapBuffer();
    }

    private BinaryWriter(int initialCapacity) {
        this.buf = PooledByteBufAllocator.DEFAULT.heapBuffer(initialCapacity);
    }

    public static byte[] write(Consumer<BinaryWriter> writer) {
        try (BinaryWriter w = new BinaryWriter()) {
            writer.accept(w);
            return w.toBytes();
        }
    }

    public BinaryWriter writeInt(int value) {
        buf.writeInt(value);
        return this;
    }

    public BinaryWriter writeLong(long value) {
        buf.writeLong(value);
        return this;
    }

    public BinaryWriter writeShort(int value) {
        buf.writeShort(value);
        return this;
    }

    public BinaryWriter writeBoolean(boolean value) {
        buf.writeBoolean(value);
        return this;
    }

    public BinaryWriter writeBytes(byte[] bytes) {
        buf.writeBytes(bytes);
        return this;
    }

    public BinaryWriter writeLengthPrefixedBytes(byte[] bytes) {
        buf.writeInt(bytes.length);
        buf.writeBytes(bytes);
        return this;
    }

    public BinaryWriter writeString(String value) {
        if (value == null) {
            buf.writeShort(-1);
            return this;
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        buf.writeShort(bytes.length);
        buf.writeBytes(bytes);
        return this;
    }

    private byte[] toBytes() {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        return bytes;
    }

    @Override
    public void close() {
        buf.release();
    }
}
