package fr.whip.bot.service;

import java.time.Instant;

public class TemporaryFileLink {
    private final String token;
    private final byte[] fileData;
    private final String fileName;
    private final Instant expiresAt;
    private boolean used;

    public TemporaryFileLink(String token, byte[] fileData, String fileName, long expirationMillis) {
        this.token = token;
        this.fileData = fileData;
        this.fileName = fileName;
        this.expiresAt = Instant.now().plusMillis(expirationMillis);
        this.used = false;
    }

    public String getToken() { return token; }
    public byte[] getFileData() { return fileData; }
    public String getFileName() { return fileName; }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt) || used;
    }

    public void markAsUsed() {
        this.used = true;
    }
}
