package gg.whip.server.service;

import fr.whip.api.model.License;
import fr.whip.api.model.Machine;
import fr.whip.api.model.Session;
import gg.whip.server.config.ServerProperties;
import gg.whip.server.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final SessionRepository sessionRepository;
    private final ServerProperties serverProperties;
    private final CryptoService cryptoService;

    private final Map<String, TemporaryClientToken> temporaryTokens = new ConcurrentHashMap<>();

    public TemporaryClientToken createTemporaryClientToken(
            fr.whip.api.model.User user,
            License license,
            Machine machine,
            String productCode,
            String hwid,
            String ipAddress,
            byte[] authSalt,
            byte[] algoSeed,
            byte[] expectedFingerprint) {

        byte[] token = cryptoService.generateRandomBytes(32);
        byte[] attestationToken = cryptoService.generateRandomBytes(32);
        TemporaryClientToken tempToken = new TemporaryClientToken();
        tempToken.setToken(token);
        tempToken.setClientAttestationToken(attestationToken);
        tempToken.setAttestationConsumed(false);
        tempToken.setAuthSalt(authSalt);
        tempToken.setAlgoSeed(algoSeed);
        tempToken.setExpectedFingerprint(expectedFingerprint);
        tempToken.setUser(user);
        tempToken.setLicense(license);
        tempToken.setMachine(machine);
        tempToken.setProductCode(productCode);
        tempToken.setHwid(hwid);
        tempToken.setIpAddress(ipAddress);
        tempToken.setCreatedAt(Instant.now());
        tempToken.setExpiresAt(Instant.now().plusSeconds(120));

        String tokenKey = bytesToHex(token);
        temporaryTokens.put(tokenKey, tempToken);

        log.info("[TOKEN_DBG] Created temporary client token for user {} — key: {}", user.getUsername(), tokenKey);
        return tempToken;
    }

    public Optional<TemporaryClientToken> findTemporaryClientToken(byte[] token) {
        String tokenKey = bytesToHex(token);
        Optional<TemporaryClientToken> result = Optional.ofNullable(temporaryTokens.get(tokenKey));
        if (result.isEmpty()) {
            log.warn("[TOKEN_DBG] findTemporaryClientToken MISS — received key: {} | map keys: {}", tokenKey, temporaryTokens.keySet());
        }
        return result;
    }

    public void deleteTemporaryClientToken(TemporaryClientToken token) {
        String tokenKey = bytesToHex(token.getToken());
        temporaryTokens.remove(tokenKey);
    }

    @Scheduled(fixedRate = 30000)
    public void cleanupExpiredTemporaryTokens() {
        Instant now = Instant.now();
        int removed = 0;
        for (var entry : temporaryTokens.entrySet()) {
            if (entry.getValue().isExpired()) {
                temporaryTokens.remove(entry.getKey());
                removed++;
            }
        }
        if (removed > 0) {
            log.debug("Cleaned up {} expired temporary tokens", removed);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    @Transactional
    public Session create(License license, Machine machine, String ip, byte[] sessionKey) {
        Session session = new Session();
        session.setLicense(license);
        session.setMachine(machine);
        session.setIp(ip);
        session.setTokenHash(cryptoService.generateTokenHash());
        session.setSessionKeyHash(cryptoService.hashNonce(sessionKey));
        session.setExpiresAt(Instant.now().plusSeconds(serverProperties.getSession().getTtlMinutes() * 60L));
        return sessionRepository.save(session);
    }

    @Transactional
    public void refreshHeartbeat(Session session) {
        session.refreshHeartbeat();
        session.setExpiresAt(Instant.now().plusSeconds(serverProperties.getSession().getTtlMinutes() * 60L));
        sessionRepository.save(session);
    }

    @Transactional
    public void end(Session session) {
        session.end();
        sessionRepository.save(session);
    }

    public boolean hasReachedSessionLimit(License license) {
        long activeCount = sessionRepository.countActiveSessions(license, Instant.now());
        return activeCount >= serverProperties.getSession().getMaxPerLicense();
    }

    public boolean hasActiveSessionForMachine(Machine machine) {
        long count = sessionRepository.countActiveSessionsByMachine(machine, Instant.now());
        return count >= serverProperties.getSession().getMaxPerMachine();
    }

    @Scheduled(fixedRateString = "${server.session.cleanup-interval-ms:60000}")
    @Transactional
    public void cleanupSessions() {
        Instant now = Instant.now();
        int expired = sessionRepository.expireOldSessions(now);
        Instant heartbeatTimeout = now.minusSeconds(serverProperties.getSession().getHeartbeatTimeoutSeconds());
        int inactive = sessionRepository.expireInactiveSessions(now, heartbeatTimeout);
        if (expired > 0 || inactive > 0) {
            log.info("Session cleanup: {} expired, {} inactive", expired, inactive);
        }
    }
}