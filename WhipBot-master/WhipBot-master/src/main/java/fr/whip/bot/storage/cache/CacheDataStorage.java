package fr.whip.bot.storage.cache;

import fr.whip.api.storage.IIdentifiable;
import fr.whip.bot.storage.IDataStorage;
import fr.whip.bot.storage.IPersistentDataStorage;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;

public class CacheDataStorage<T extends IIdentifiable> implements IDataStorage<T> {

    protected final IPersistentDataStorage<T> delegate;
    protected final ScheduledExecutorService executor;
    protected final Map<UUID, T> cache;

    public CacheDataStorage(IPersistentDataStorage<T> delegate, ScheduledExecutorService executor) {
        this.delegate = delegate;
        this.executor = executor;
        this.cache = new ConcurrentHashMap<>();
    }

    @Override
    public void start() {
        delegate.start();
    }

    @Override
    public void stop() {
        executor.shutdownNow().forEach(Runnable::run);
        delegate.stop();
    }

    @Override
    public T save(T data) {
        T saved = delegate.save(data);
        if (saved != null && saved.getId() != null) {
            cache.put(saved.getId(), saved);
        }
        return saved;
    }

    @Override
    public Optional<T> get(UUID id) {
        T cached = cache.get(id);
        if (cached != null) {
            return Optional.of(cached);
        }
        return delegate.get(id).map(value -> {
            cache.put(id, value);
            return value;
        });
    }

    @Override
    public void delete(UUID id) {
        cache.remove(id);
        executor.execute(() -> delegate.delete(id));
    }

    @Override
    public List<T> loadAll() {
        List<T> values = delegate.loadAll();
        values.forEach(v -> cache.put(v.getId(), v));
        return values;
    }

    public CompletableFuture<Optional<T>> getAsync(UUID id) {
        T cached = cache.get(id);
        if (cached != null) {
            return CompletableFuture.completedFuture(Optional.of(cached));
        }
        return CompletableFuture.supplyAsync(() -> delegate.get(id).map(value -> {
            cache.put(id, value);
            return value;
        }), executor);
    }

    public boolean hasKey(UUID id) {
        return cache.containsKey(id);
    }

    public void clearCache() {
        cache.clear();
    }

    public void evict(UUID id) {
        cache.remove(id);
    }

    public Optional<T> refresh(UUID id) {
        cache.remove(id);
        return delegate.get(id).map(value -> {
            cache.put(id, value);
            return value;
        });
    }

    public Map<UUID, T> getCache() {
        return cache;
    }
}
