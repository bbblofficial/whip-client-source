package gg.whip.server.service;

import fr.whip.api.model.Config;
import fr.whip.api.model.User;
import fr.whip.api.model.UserConfig;
import fr.whip.api.model.UserConfigId;
import gg.whip.server.data.ConfigResponseData;
import gg.whip.server.repository.ConfigRepository;
import gg.whip.server.repository.UserConfigRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class ConfigStorageService {

    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ConfigRepository configRepository;
    private final UserConfigRepository userConfigRepository;

    @Transactional
    public ConfigResponseData create(User user, String configId, String name, String description, String author, byte[] data) {
        if (name == null || name.isBlank()) {
            return ConfigResponseData.error((byte) 0, "Config name is required");
        }
        if (data == null || data.length == 0) {
            return ConfigResponseData.error((byte) 0, "Config data is required");
        }

        UUID id;
        try {
            id = UUID.fromString(configId);
        } catch (Exception e) {
            id = UUID.randomUUID();
        }

        if (configRepository.existsById(id)) {
            return ConfigResponseData.error((byte) 0, "Config already exists");
        }

        LocalDateTime now = LocalDateTime.now();

        Config config = new Config();
        config.setId(id);
        config.setName(name);
        config.setDescription(description);
        config.setData(new String(data, StandardCharsets.UTF_8));
        config.setPublic(false);
        config.setCreatedAt(now);
        config.setUpdatedAt(now);
        configRepository.save(config);

        UserConfig userConfig = new UserConfig();
        UserConfigId ucId = new UserConfigId();
        ucId.setUserId(user.getId());
        ucId.setConfigId(config.getId());
        userConfig.setId(ucId);
        userConfig.setUser(user);
        userConfig.setConfig(config);
        userConfig.setOwner(true);
        userConfig.setAddedAt(now);
        userConfigRepository.save(userConfig);

        log.info("Config created: id={}, name='{}', user={}", config.getId(), name, user.getUsername());
        return ConfigResponseData.success((byte) 0, config.getId().toString());
    }

    @Transactional(readOnly = true)
    public ConfigResponseData load(User user, String configId) {
        if (configId == null || configId.isBlank()) {
            return ConfigResponseData.error((byte) 1, "Config ID is required");
        }

        UUID id;
        try {
            id = UUID.fromString(configId);
        } catch (Exception e) {
            return ConfigResponseData.error((byte) 1, "Invalid config ID");
        }

        Optional<Config> configOpt = configRepository.findById(id);
        if (configOpt.isEmpty()) {
            return ConfigResponseData.error((byte) 1, "Config not found");
        }

        Config config = configOpt.get();

        // Check access: owner or public
        if (!config.isPublic() && !userConfigRepository.existsByUserAndConfig(user, config)) {
            return ConfigResponseData.error((byte) 1, "Access denied");
        }

        byte[] configData = config.getData().getBytes(StandardCharsets.UTF_8);
        log.debug("Config loaded: id={}, user={}, size={}", configId, user.getUsername(), configData.length);
        return ConfigResponseData.successWithData((byte) 1, configData);
    }

    @Transactional
    public ConfigResponseData delete(User user, String configId) {
        if (configId == null || configId.isBlank()) {
            return ConfigResponseData.error((byte) 2, "Config ID is required");
        }

        UUID id;
        try {
            id = UUID.fromString(configId);
        } catch (Exception e) {
            return ConfigResponseData.error((byte) 2, "Invalid config ID");
        }

        Optional<Config> configOpt = configRepository.findById(id);
        if (configOpt.isEmpty()) {
            return ConfigResponseData.error((byte) 2, "Config not found");
        }

        Config config = configOpt.get();

        // Check ownership
        Optional<UserConfig> ucOpt = userConfigRepository.findByUserAndConfig(user, config);
        if (ucOpt.isEmpty() || !ucOpt.get().isOwner()) {
            return ConfigResponseData.error((byte) 2, "Only the owner can delete a config");
        }

        configRepository.delete(config);
        log.info("Config deleted: id={}, user={}", configId, user.getUsername());
        return ConfigResponseData.success((byte) 2, "Config deleted");
    }

    @Transactional
    public ConfigResponseData update(User user, String configId, byte[] data) {
        if (configId == null || configId.isBlank()) {
            return ConfigResponseData.error((byte) 3, "Config ID is required");
        }
        if (data == null || data.length == 0) {
            return ConfigResponseData.error((byte) 3, "Config data is required");
        }

        UUID id;
        try {
            id = UUID.fromString(configId);
        } catch (Exception e) {
            return ConfigResponseData.error((byte) 3, "Invalid config ID");
        }

        Optional<Config> configOpt = configRepository.findById(id);
        if (configOpt.isEmpty()) {
            return ConfigResponseData.error((byte) 3, "Config not found");
        }

        Config config = configOpt.get();

        // Check ownership
        Optional<UserConfig> ucOpt = userConfigRepository.findByUserAndConfig(user, config);
        if (ucOpt.isEmpty() || !ucOpt.get().isOwner()) {
            return ConfigResponseData.error((byte) 3, "Only the owner can modify a config");
        }

        config.setData(new String(data, StandardCharsets.UTF_8));
        config.setUpdatedAt(LocalDateTime.now());
        configRepository.save(config);

        log.info("Config updated: id={}, user={}", configId, user.getUsername());
        return ConfigResponseData.success((byte) 3, "Config updated");
    }

    @Transactional(readOnly = true)
    public ConfigResponseData listForUser(User user) {
        List<UserConfig> userConfigs = userConfigRepository.findByUser(user);

        List<ConfigResponseData.ConfigEntry> entries = userConfigs.stream()
                .map(uc -> {
                    Config c = uc.getConfig();
                    return new ConfigResponseData.ConfigEntry(
                            c.getId().toString(),
                            c.getName(),
                            c.getDescription(),
                            user.getUsername(),
                            c.getCreatedAt() != null ? c.getCreatedAt().format(DATE_FORMAT) : "",
                            c.getUpdatedAt() != null ? c.getUpdatedAt().format(DATE_FORMAT) : ""
                    );
                })
                .toList();

        log.debug("Listed {} configs for user {}", entries.size(), user.getUsername());
        return ConfigResponseData.successWithEntries((byte) 4, entries);
    }
}
