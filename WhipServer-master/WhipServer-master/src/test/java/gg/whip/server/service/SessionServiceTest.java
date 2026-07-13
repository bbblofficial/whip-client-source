package gg.whip.server.service;

import fr.whip.api.model.License;
import fr.whip.api.model.Machine;
import gg.whip.server.config.ServerProperties;
import gg.whip.server.repository.SessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionServiceTest {

    @Mock
    private SessionRepository sessionRepository;

    @Mock
    private CryptoService cryptoService;

    private ServerProperties serverProperties;
    private SessionService sessionService;

    @BeforeEach
    void setUp() {
        serverProperties = new ServerProperties();
        serverProperties.getSession().setMaxPerLicense(1);
        serverProperties.getSession().setMaxPerMachine(2);
        sessionService = new SessionService(sessionRepository, serverProperties, cryptoService);
    }

    // ========== HAS ACTIVE SESSION FOR MACHINE ==========

    @Nested
    @DisplayName("Multi-Instance Detection (hasActiveSessionForMachine)")
    class MultiInstanceDetection {

        @Mock
        private Machine machine;

        @Test
        @DisplayName("Returns false when machine has fewer sessions than maxPerMachine")
        void returnsFalseWhenBelowMachineLimit() {
            when(sessionRepository.countActiveSessionsByMachine(eq(machine), any(Instant.class)))
                    .thenReturn(1L);

            assertFalse(sessionService.hasActiveSessionForMachine(machine));
        }

        @Test
        @DisplayName("Returns true when machine has reached maxPerMachine")
        void returnsTrueWhenMachineLimitReached() {
            when(sessionRepository.countActiveSessionsByMachine(eq(machine), any(Instant.class)))
                    .thenReturn(2L);

            assertTrue(sessionService.hasActiveSessionForMachine(machine));
        }

        @Test
        @DisplayName("Returns true when machine exceeds maxPerMachine")
        void returnsTrueWhenMachineLimitExceeded() {
            when(sessionRepository.countActiveSessionsByMachine(eq(machine), any(Instant.class)))
                    .thenReturn(3L);

            assertTrue(sessionService.hasActiveSessionForMachine(machine));
        }

        @Test
        @DisplayName("Returns false when machine has no active session")
        void returnsFalseWhenMachineHasNoActiveSession() {
            when(sessionRepository.countActiveSessionsByMachine(eq(machine), any(Instant.class)))
                    .thenReturn(0L);

            assertFalse(sessionService.hasActiveSessionForMachine(machine));
        }
    }

    // ========== HAS REACHED SESSION LIMIT ==========

    @Nested
    @DisplayName("Session Limit (hasReachedSessionLimit)")
    class SessionLimit {

        @Mock
        private License license;

        @Test
        @DisplayName("Returns true when active sessions >= max per license")
        void returnsTrueWhenLimitReached() {
            when(sessionRepository.countActiveSessions(eq(license), any(Instant.class)))
                    .thenReturn(1L);

            assertTrue(sessionService.hasReachedSessionLimit(license));
        }

        @Test
        @DisplayName("Returns false when active sessions < max per license")
        void returnsFalseWhenBelowLimit() {
            when(sessionRepository.countActiveSessions(eq(license), any(Instant.class)))
                    .thenReturn(0L);

            assertFalse(sessionService.hasReachedSessionLimit(license));
        }

        @Test
        @DisplayName("Returns true when active sessions exceed max per license")
        void returnsTrueWhenExceedingLimit() {
            serverProperties.getSession().setMaxPerLicense(3);
            when(sessionRepository.countActiveSessions(eq(license), any(Instant.class)))
                    .thenReturn(5L);

            assertTrue(sessionService.hasReachedSessionLimit(license));
        }
    }

    // ========== MULTI-INSTANCE VS SESSION LIMIT INDEPENDENCE ==========

    @Nested
    @DisplayName("Multi-Instance and Session Limit are independent")
    class IndependenceTest {

        @Mock
        private Machine machine;

        @Mock
        private License license;

        @Test
        @DisplayName("Machine can be blocked even when license has no sessions")
        void machineBlockedLicenseOk() {
            when(sessionRepository.countActiveSessionsByMachine(eq(machine), any(Instant.class)))
                    .thenReturn(2L);
            when(sessionRepository.countActiveSessions(eq(license), any(Instant.class)))
                    .thenReturn(0L);

            assertTrue(sessionService.hasActiveSessionForMachine(machine));
            assertFalse(sessionService.hasReachedSessionLimit(license));
        }

        @Test
        @DisplayName("License can be blocked even when machine has no sessions")
        void licenseBlockedMachineOk() {
            when(sessionRepository.countActiveSessionsByMachine(eq(machine), any(Instant.class)))
                    .thenReturn(0L);
            when(sessionRepository.countActiveSessions(eq(license), any(Instant.class)))
                    .thenReturn(1L);

            assertFalse(sessionService.hasActiveSessionForMachine(machine));
            assertTrue(sessionService.hasReachedSessionLimit(license));
        }
    }
}
