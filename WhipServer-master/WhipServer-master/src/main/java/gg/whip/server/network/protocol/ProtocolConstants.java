package gg.whip.server.network.protocol;

public final class ProtocolConstants {

    public static final byte[] MAGIC = new byte[] { 'P', 'I', 'H', 'W' };
    public static final short VERSION = 1;

    public static final int HEADER_SIZE = 24;
    public static final int HMAC_SIZE = 32;
    public static final int NONCE_SIZE = 12;

    public static final int MAX_PACKET_SIZE = 1048576; // 1MB
}
