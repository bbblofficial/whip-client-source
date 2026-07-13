package gg.whip.server.data;

public record ClientHelloData(int version, byte[] nonce, byte[] publicKey) {}