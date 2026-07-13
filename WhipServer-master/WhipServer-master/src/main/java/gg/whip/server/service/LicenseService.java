package gg.whip.server.service;

import fr.whip.api.model.License;
import fr.whip.api.model.LicenseStatus;
import fr.whip.api.model.Product;
import fr.whip.api.model.ProductType;
import fr.whip.api.model.User;
import gg.whip.server.repository.LicenseRepository;
import gg.whip.server.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class LicenseService {

    private final LicenseRepository licenseRepository;
    private final ProductRepository productRepository;

    @Transactional(readOnly = true)
    public Optional<License> findByKey(String licenseKey) {
        return licenseRepository.findByLicenseKey(licenseKey);
    }

    @Transactional(readOnly = true)
    public List<License> findActiveLicenses(User user) {
        return licenseRepository.findByUserAndStatus(user, LicenseStatus.active);
    }

    @Transactional(readOnly = true)
    public Optional<License> findValidLicense(User user, String productCode) {
        try {
            // Convertir le String en enum ProductType
            ProductType productType = ProductType.valueOf(productCode);
            Optional<Product> product = productRepository.findByCode(productType);
            return product.flatMap(value -> licenseRepository.findByUser(user).stream()
                    .filter(l -> l.getProduct().equals(value))
                    .filter(License::isValid)
                    .findFirst());
        } catch (IllegalArgumentException e) {
            // ProductCode invalide (pas dans l'enum ProductType)
            return Optional.empty();
        }
    }

    @Transactional
    public void suspend(License license) {
        license.setStatus(LicenseStatus.suspended);
        licenseRepository.save(license);
    }

    @Transactional
    public void revoke(License license) {
        license.setStatus(LicenseStatus.revoked);
        licenseRepository.save(license);
    }
}
