package gg.whip.server.repository;

import fr.whip.api.model.Config;
import fr.whip.api.model.User;
import fr.whip.api.model.UserConfig;
import fr.whip.api.model.UserConfigId;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserConfigRepository extends JpaRepository<UserConfig, UserConfigId> {

    List<UserConfig> findByUser(User user);

    Optional<UserConfig> findByUserAndConfig(User user, Config config);

    boolean existsByUserAndConfig(User user, Config config);
}
