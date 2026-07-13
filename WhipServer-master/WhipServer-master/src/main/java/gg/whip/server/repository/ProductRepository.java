package gg.whip.server.repository;

import fr.whip.api.model.Product;
import fr.whip.api.model.ProductType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ProductRepository extends JpaRepository<Product, UUID> {

    Optional<Product> findByCode(ProductType code);

    boolean existsByCode(ProductType code);
}
