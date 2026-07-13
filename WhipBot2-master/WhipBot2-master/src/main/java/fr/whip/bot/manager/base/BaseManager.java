package fr.whip.bot.manager.base;

import fr.whip.api.storage.IIdentifiable;
import fr.whip.bot.storage.cache.CacheDataStorage;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public abstract class BaseManager<T extends IIdentifiable> {

    protected final CacheDataStorage<T> storage;

    protected BaseManager(CacheDataStorage<T> storage) {
        this.storage = storage;
    }

    public void start() {
        storage.start();
    }

    public void stop() {
        storage.stop();
    }

    public T save(T value) {
        return storage.save(value);
    }

    public Optional<T> get(UUID id) {
        return storage.get(id);
    }

    public CompletableFuture<Optional<T>> getAsync(UUID id) {
        return storage.getAsync(id);
    }

    public void delete(UUID id) {
        storage.delete(id);
    }

    public void delete(T value) {
        delete(value.getId());
    }

    public List<T> loadAll() {
        return storage.loadAll();
    }

    public Collection<T> findAll() {
        return storage.getCache().values();
    }

    public boolean hasKey(UUID id) {
        return storage.hasKey(id);
    }

    public void clearCache() {
        storage.clearCache();
    }

    public Map<UUID, T> getCache() {
        return storage.getCache();
    }

    public CacheDataStorage<T> getStorage() {
        return storage;
    }
}