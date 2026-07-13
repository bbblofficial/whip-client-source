package gg.whip.server.data;

import fr.whip.api.model.*;
import io.netty.channel.Channel;
import lombok.Getter;
import lombok.Setter;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Getter
@Setter
public class ClientSession {

    private final Channel channel;
    private final String remoteAddress;
    private final String ip;

    private SessionState state = SessionState.CONNECTED;

    private String tempSessionId;
    private byte[] serverNonce;
    private KeyPair serverKeyPair;
    private byte[] clientNonce;
    private byte[] clientPublicKey;

    private byte[] sendKey;
    private byte[] recvKey;
    private byte[] pendingChallenge;
    private byte[] userSecret;  // Per-session secret for auth HMAC
    private byte[] sessionToken; // 32-byte token sent to client at auth — also
                                 // bound into Ed25519-signed setting mutations.
    private String productCode;
    private String hwid;  // Real HWID from client (stored during init)

    // Remote-blessed settings — in-memory only (no DB), per-session.
    // Sequence counter is bumped on every signed mutation and bound into
    // the canonical payload so a replay of an older response fails the
    // strict-monotonic check on the client.
    private final AtomicLong settingSequenceCounter = new AtomicLong(0);
    // Per-(settingKey) token bucket for mass-toggle defence. Concurrent
    // because the receive thread mutates from any worker.
    private final ConcurrentHashMap<String, SettingTokenBucket> settingTokenBuckets =
            new ConcurrentHashMap<>();

    private Download download;
    private User user;
    private License license;
    private Machine machine;
    private Session dbSession;
    private int permissions;

    // In-memory only — not persisted to DB, used for webhooks
    private String mcUsername;

    // Rempli par les handlers quand la session est rejetée.
    // Consommé par ConnectFailReportHandler pour notifier Discord avec screenshot.
    private String blockReportReason;
    private String blockReportPcName;
    private String blockReportExe;
    // Username du propriétaire de l'exe quand l'user n'est pas encore sur la session
    // (ex. HWID mismatch : on sait à qui appartient le download mais pas encore .setUser())
    private String blockReportUsername;

    // File download sequence — populated after product select
    // Each FILE_REQUEST pops the next key from this sequence
    private final List<String> fileDownloadSequence = new ArrayList<>();
    private int fileDownloadIndex = 0;

    public ClientSession(Channel channel) {
        this.channel = channel;
        String addr = channel.remoteAddress().toString();
        this.remoteAddress = addr.startsWith("/") ? addr.substring(1) : addr;
        int colonIndex = remoteAddress.indexOf(':');
        this.ip = colonIndex > 0 ? remoteAddress.substring(0, colonIndex) : remoteAddress;
    }

    public void send(RawPacket packet) {
        if (channel.isActive()) {
            channel.writeAndFlush(packet);
        }
    }

    public void close() {
        if (channel.isActive()) {
            channel.close();
        }
    }

    public boolean isAuthenticated() {
        return state == SessionState.AUTHENTICATED;
    }

    public boolean isIpChanged(String currentIp) {
        return dbSession != null && !dbSession.getIp().equals(currentIp);
    }

    /**
     * Returns the next file key in the download sequence, or null if exhausted.
     * Advances the index for the next call.
     */
    public String nextFileKey() {
        if (fileDownloadIndex >= fileDownloadSequence.size()) {
            return null;
        }
        return fileDownloadSequence.get(fileDownloadIndex++);
    }

    public void setFileDownloadSequence(List<String> sequence) {
        fileDownloadSequence.clear();
        fileDownloadSequence.addAll(sequence);
        fileDownloadIndex = 0;
    }

    /**
     * Check if a file key is authorized for this session.
     * Delegates to {@link Product#isKeyAuthorized(String)} which checks
     * loader files, client files, and dynamic patterns (mappings).
     */
    public boolean isFileKeyAuthorized(String key) {
        Product product = Product.fromCode(productCode);
        if (product == null) {
            return false;
        }
        return product.isKeyAuthorized(key);
    }

    public void setSessionKey(byte[] key) {
        this.sendKey = key.clone();
        this.recvKey = key.clone();
    }

    public byte[] getSessionKey() {
        return recvKey;
    }

    public enum SessionState {
        CONNECTED,
        HELLO_DONE,
        INIT_DONE,
        AUTHENTICATED,
        DISCONNECTED
    }
}