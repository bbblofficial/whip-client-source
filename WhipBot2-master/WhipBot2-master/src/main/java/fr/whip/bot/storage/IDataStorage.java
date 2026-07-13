package fr.whip.bot.storage;

import fr.whip.api.storage.IIdentifiable;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface IDataStorage<T extends IIdentifiable> {

    void start();

    void stop();

    T save(T data);

    Optional<T> get(UUID id);

    void delete(UUID id);

    List<T> loadAll();
}