package gg.whip.server.repository;

import fr.whip.api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);

    Optional<User> findByDiscordId(String discordId);

    boolean existsByUsername(String username);
}