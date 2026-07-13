package gg.whip.server.service;

import fr.whip.api.model.UsedNonce;
import fr.whip.api.model.UsedRequest;
import gg.whip.server.config.ServerProperties;
import gg.whip.server.repository.UsedNonceRepository;
import gg.whip.server.repository.UsedRequestRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AntiReplayService {

    private final UsedRequestRepository usedRequestRepository;
    private final UsedNonceRepository usedNonceRepository;
    private final ServerProperties serverProperties;
    private final CryptoService cryptoService;

    @Transactional
    public boolean checkAndMarkRequestId(UUID requestId, UUID sessionId) {
        try {
            usedRequestRepository.save(new UsedRequest(requestId, sessionId));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Transactional
    public boolean checkAndMarkNonce(byte[] nonce, UUID sessionId) {
        try {
            String nonceHash = cryptoService.hashNonce(nonce);
            if (usedNonceRepository.existsByNonceHash(nonceHash)) {
                return false;
            }

            usedNonceRepository.save(new UsedNonce(nonceHash, sessionId));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Scheduled(fixedRateString = "${server.security.cleanup-interval-ms:300000}")
    @Transactional
    public void cleanup() {
        Instant cutoff = Instant.now().minusSeconds(
                serverProperties.getSecurity().getRequestIdRetentionMinutes() * 60L
        );
        usedRequestRepository.deleteOldRequests(cutoff);
        usedNonceRepository.deleteOldNonces(cutoff);
    }

    public boolean isTimestampValid(long timestamp) {
        long now = Instant.now().getEpochSecond();
        long tolerance = serverProperties.getSecurity().getTimestampToleranceSeconds();
        return Math.abs(now - timestamp) <= tolerance;
    }
}