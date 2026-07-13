package gg.whip.server.service.auth;

import fr.whip.api.model.License;
import fr.whip.api.model.Machine;
import fr.whip.api.model.User;
import gg.whip.server.data.AuthRequest;
import gg.whip.server.data.AuthResult;
import gg.whip.server.data.Product;
import gg.whip.server.repository.UserRepository;
import gg.whip.server.service.AuthenticationService.AuthError;
import gg.whip.server.service.BlacklistService;
import gg.whip.server.service.LicenseService;
import gg.whip.server.service.MachineService;
import gg.whip.server.service.SessionService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class HwidOnlyAuthStrategy implements ProductAuthStrategy {

    private final UserRepository userRepository;
    private final MachineService machineService;
    private final LicenseService licenseService;
    private final SessionService sessionService;
    private final BlacklistService blacklistService;

    @Override
    public Product product() {
        return Product.WHIP_BYPASS;
    }

    @Override
    public AuthResult authenticate(AuthRequest request) {
        Optional<User> userOpt = userRepository.findByUsername(request.username());
        if (userOpt.isEmpty()) {
            return AuthResult.failure(AuthError.INVALID_CREDENTIALS);
        }
        User user = userOpt.get();

        if (blacklistService.isBlacklisted(user)) {
            return AuthResult.failure(AuthError.USER_BLACKLISTED);
        }

        Optional<License> licenseOpt = licenseService.findValidLicense(user, request.productCode());
        if (licenseOpt.isEmpty()) {
            return AuthResult.failure(AuthError.NO_VALID_LICENSE);
        }
        License license = licenseOpt.get();

        Optional<Machine> machineOpt = machineService.findByUserAndHwid(user, request.hwid());
        if (machineOpt.isEmpty()) {
            return AuthResult.failure(AuthError.INVALID_CREDENTIALS);
        }
        Machine machine = machineOpt.get();

        if (machine.getRevokedAt() != null) {
            return AuthResult.failure(AuthError.MACHINE_REVOKED);
        }
        machineService.updateLastSeen(machine);

        if (sessionService.hasReachedSessionLimit(license)) {
            return AuthResult.failure(AuthError.SESSION_LIMIT_REACHED);
        }

        return AuthResult.success(user, license, machine);
    }
}
