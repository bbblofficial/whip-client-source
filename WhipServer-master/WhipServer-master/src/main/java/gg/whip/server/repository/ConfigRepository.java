package gg.whip.server.repository;

import fr.whip.api.model.Config;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface ConfigRepository extends JpaRepository<Config, UUID> {
}
