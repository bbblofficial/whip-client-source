package gg.whip.server.data;

public record AuthRequest(String username, String password, String hwid, String productCode, String pcName, String os)
{}