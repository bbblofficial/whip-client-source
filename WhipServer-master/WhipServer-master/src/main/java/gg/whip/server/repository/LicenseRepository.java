package gg.whip.server.repository;

import fr.whip.api.model.License;
import fr.whip.api.model.LicenseStatus;
import fr.whip.api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface LicenseRepository extends JpaRepository<License, UUID> {

    Optional<License> findByLicenseKey(String licenseKey);

    List<License> findByUser(User user);

    List<License> findByUserAndStatus(User user, LicenseStatus status);

    boolean existsByLicenseKey(String licenseKey);
}
