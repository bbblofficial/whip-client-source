package fr.whip.api.model;

import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@Embeddable
public class UserConfigId implements Serializable {

    private UUID userId;
    private UUID configId;

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        UserConfigId that = (UserConfigId) o;
        return Objects.equals(userId, that.userId) && Objects.equals(configId, that.configId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, configId);
    }
}