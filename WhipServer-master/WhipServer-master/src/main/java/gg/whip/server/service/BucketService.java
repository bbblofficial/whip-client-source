package gg.whip.server.service;

import gg.whip.server.config.ServerProperties;
import gg.whip.server.data.ClientSession;
import gg.whip.server.data.DownloadableFile;
import gg.whip.server.data.FileChunkData;
import gg.whip.server.data.FileChunkMetaData;
import gg.whip.server.data.Product;
import gg.whip.server.exception.CryptoException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.Deflater;

@Slf4j
@Service
@RequiredArgsConstructor
public class BucketService {

    private static final int GCM_TAG_LENGTH = 128;
    private static final int NONCE_LENGTH = 12;
    private static final Pattern VALID_VERSION_PATTERN = Pattern.compile("^v[0-9]+(_[0-9]+)*$");
    private static final Set<String> VALID_PLATFORMS = Set.of("lunar", "badlion", "vanilla", "cheatbreaker", "forge");

    private static final int CHUNK_SIZE = 2 * 1024 * 1024;

    /**
     * Below this threshold compression is not worth the CPU/latency tax —
     * the wire saving on a few KB doesn't beat the DEFLATE setup cost,
     * and small payloads (e.g. mappings shards) often round-trip in one
     * chunk anyway.
     */
    private static final int COMPRESSION_MIN_SIZE = 64 * 1024;

    /**
     * Result of an opportunistic compression pass. {@code payload} is what
     * actually gets chunked + encrypted. When {@code compressed} is false
     * (data smaller than the threshold, or DEFLATE didn't help), payload
     * is just the original bytes — caller treats both paths uniformly.
     */
    public record CompressedBlob(byte[] payload, int originalSize, boolean compressed) {
        public int payloadSize() { return payload.length; }
    }

    private static final ThreadLocal<Cipher> AES_GCM_CIPHER = ThreadLocal.withInitial(() -> {
        try { return Cipher.getInstance("AES/GCM/NoPadding"); } catch (Exception e) { throw new RuntimeException(e); }
    });

    private final ServerProperties serverProperties;
    private final SecureRandom secureRandom = new SecureRandom();

    public Path resolveForSession(String key, ClientSession session) {
        return resolve(key);
    }

    public boolean fileExistsAt(Path path) {
        return path != null && Files.exists(path) && Files.isRegularFile(path);
    }

    public FileChunkMetaData prepareChunkMetaForPath(String key, Path filePath) throws IOException {
        if (filePath == null || !Files.exists(filePath)) {
            throw new IOException("File not found for key '" + key + "'");
        }
        int fileSize = (int) Files.size(filePath);
        int chunkCount = (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
        log.info("Prepared chunk meta for '{}' at {}: {} chunks, {} bytes total", key, filePath, chunkCount, fileSize);
        return FileChunkMetaData.create(key, fileSize, fileSize, chunkCount, CHUNK_SIZE, false);
    }

    public Path resolve(String key) {
        DownloadableFile file = DownloadableFile.fromKey(key);
        if (file != null && !file.getBucketPath().isEmpty()) {
            return Paths.get(file.getBucketPath());
        }

        if (key.startsWith("mappings-")) {
            String[] parts = key.substring("mappings-".length()).split("-", 2);
            if (parts.length == 2
                    && VALID_VERSION_PATTERN.matcher(parts[0]).matches()
                    && VALID_PLATFORMS.contains(parts[1])) {
                return Paths.get("/bucket/mappings/" + parts[0] + "/" + parts[1] + ".wbin");
            }
            log.warn("Invalid mappings key '{}': version='{}' platform='{}'",
                    key, parts.length > 0 ? parts[0] : "?", parts.length > 1 ? parts[1] : "?");
        }

        return null;
    }




    public boolean fileExists(String key) {
        Path path = resolve(key);
        boolean exists = path != null && Files.exists(path) && Files.isRegularFile(path);
        log.debug("fileExists('{}') -> exists={}", key, exists);
        return exists;
    }

    public long getFileSize(String key) {
        try {
            Path path = resolve(key);
            if (path == null || !Files.exists(path)) return -1;
            return Files.size(path);
        } catch (IOException e) {
            log.warn("Failed to get file size for key '{}'", key, e);
            return -1;
        }
    }

    /** Single-shot AES-GCM encrypt of an in-memory blob (nonce || ct || tag). */
    public byte[] encryptOneShot(byte[] data, byte[] sessionKey) throws CryptoException {
        return encrypt(data, sessionKey);
    }

    public byte[] getEncryptedFileAt(Path filePath, byte[] sessionKey) throws IOException, CryptoException {
        if (filePath == null || !Files.exists(filePath)) {
            throw new IOException("File not found: " + filePath);
        }
        byte[] fileBytes = Files.readAllBytes(filePath);
        log.debug("Read {} bytes from {}", fileBytes.length, filePath);
        byte[] encrypted = encrypt(fileBytes, sessionKey);
        log.debug("Encrypted {}: {} -> {} bytes", filePath, fileBytes.length, encrypted.length);
        return encrypted;
    }

    public byte[] getEncryptedFile(String key, byte[] sessionKey) throws IOException, CryptoException {
        Path filePath = resolve(key);
        if (filePath == null) {
            throw new IOException("Unknown file key: " + key);
        }

        if (!Files.exists(filePath)) {
            throw new IOException("File not found for key '" + key + "'");
        }

        byte[] fileBytes = Files.readAllBytes(filePath);
        log.debug("Read {} bytes for key '{}'", fileBytes.length, key);

        byte[] encrypted = encrypt(fileBytes, sessionKey);
        log.debug("Encrypted key '{}': {} -> {} bytes", key, fileBytes.length, encrypted.length);

        return encrypted;
    }

    public byte[] readRawFile(String key) throws IOException {
        Path filePath = resolve(key);
        if (filePath == null) {
            throw new IOException("Unknown file key: " + key);
        }
        if (!Files.exists(filePath)) {
            throw new IOException("File not found for key '" + key + "'");
        }
        return Files.readAllBytes(filePath);
    }

    public List<String> discoverDownloadSequence(String productCode) {
        Product product = Product.fromCode(productCode);
        if (product == null) {
            log.warn("Unknown product code '{}', returning empty download sequence", productCode);
            return List.of();
        }

        List<String> sequence = product.getLoaderDownloadSequence();
        log.info("Download sequence for product '{}' ({}): {}", productCode, product.name(), sequence);
        return sequence;
    }

    private byte[] encrypt(byte[] plain, byte[] sessionKey) throws CryptoException {
        try {
            byte[] nonce = new byte[NONCE_LENGTH];
            secureRandom.nextBytes(nonce);

            Cipher cipher = AES_GCM_CIPHER.get();
            SecretKeySpec keySpec = new SecretKeySpec(sessionKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            byte[] ciphertext = cipher.doFinal(plain);

            byte[] result = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, result, 0, nonce.length);
            System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);

            return result;
        } catch (Exception e) {
            throw new CryptoException("File encryption failed: " + e.getMessage(), e);
        }
    }

    public FileChunkMetaData prepareChunkMeta(String key) throws IOException {
        Path filePath = resolve(key);
        if (filePath == null) {
            throw new IOException("Unknown file key: " + key);
        }
        if (!Files.exists(filePath)) {
            throw new IOException("File not found for key '" + key + "'");
        }

        int fileSize = (int) Files.size(filePath);
        int chunkCount = (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE;

        log.info("Prepared chunk meta for '{}': {} chunks, {} bytes total", key, chunkCount, fileSize);

        return FileChunkMetaData.create(key, fileSize, fileSize, chunkCount, CHUNK_SIZE, false);
    }

    public FileChunkData readAndEncryptChunk(String key, int chunkIndex, byte[] sessionKey,
                                              RandomAccessFile raf, long fileSize)
            throws IOException, CryptoException {
        long offset = (long) chunkIndex * CHUNK_SIZE;
        int length = (int) Math.min(CHUNK_SIZE, fileSize - offset);

        byte[] chunkData = new byte[length];
        raf.seek(offset);
        raf.readFully(chunkData);

        byte[] encrypted = encrypt(chunkData, sessionKey);
        return FileChunkData.create(key, chunkIndex, encrypted);
    }

    /** In-memory variant for the watermark path: chunk meta from a byte[]. */
    public FileChunkMetaData prepareChunkMetaForBytes(String key, byte[] bytes) {
        int chunkCount = (bytes.length + CHUNK_SIZE - 1) / CHUNK_SIZE;
        log.info("Prepared chunk meta for '{}' (in-memory): {} chunks, {} bytes total",
                key, chunkCount, bytes.length);
        return FileChunkMetaData.create(key, bytes.length, bytes.length, chunkCount, CHUNK_SIZE, false);
    }

    /** In-memory variant of {@link #readAndEncryptChunk}: source is a byte[]. */
    public FileChunkData encryptChunkFromBytes(String key, int chunkIndex, byte[] sessionKey,
                                                byte[] bytes) throws CryptoException {
        long offset = (long) chunkIndex * CHUNK_SIZE;
        int length = (int) Math.min(CHUNK_SIZE, bytes.length - offset);
        byte[] chunkData = new byte[length];
        System.arraycopy(bytes, (int) offset, chunkData, 0, length);
        byte[] encrypted = encrypt(chunkData, sessionKey);
        return FileChunkData.create(key, chunkIndex, encrypted);
    }

    // ────────────────────────────────────────────────────────────────────
    // DEFLATE compression — applied before chunking + AES-GCM, so the
    // wire format is a sequence of N encrypted chunks whose decrypted
    // concatenation forms the *compressed* blob. The loader inflates
    // the blob once all N chunks are received. Untouched if the source
    // is below COMPRESSION_MIN_SIZE or if DEFLATE doesn't actually help.
    // ────────────────────────────────────────────────────────────────────

    /** Raw DEFLATE (zlib-wrapped) compression at BEST_COMPRESSION. */
    private byte[] deflate(byte[] data) {
        Deflater def = new Deflater(Deflater.BEST_COMPRESSION);
        try {
            def.setInput(data);
            def.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(data.length, 1 << 20));
            byte[] buf = new byte[64 * 1024];
            while (!def.finished()) {
                int n = def.deflate(buf);
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            def.end();
        }
    }

    /**
     * Run DEFLATE if it's worth it. Returns a {@link CompressedBlob} with
     * {@code compressed=true} only when the result is both above the size
     * threshold and meaningfully smaller than the source. Otherwise the
     * payload is the original bytes — caller doesn't need to branch on
     * which path produced them.
     */
    public CompressedBlob compressIfWorthwhile(byte[] data) {
        if (data.length < COMPRESSION_MIN_SIZE) {
            return new CompressedBlob(data, data.length, false);
        }
        byte[] deflated = deflate(data);
        // Bail if DEFLATE didn't save at least a few percent — pre-compressed
        // payloads (PNG, .lz4, encrypted blobs) blow up by a few % when run
        // through DEFLATE; shipping them raw is faster *and* smaller.
        if (deflated.length >= (int) (data.length * 0.97)) {
            log.debug("DEFLATE not worth it: {} -> {} bytes ({}%), shipping raw",
                    data.length, deflated.length,
                    (deflated.length * 100) / Math.max(1, data.length));
            return new CompressedBlob(data, data.length, false);
        }
        log.info("Compressed blob: {} -> {} bytes ({}% of original)",
                data.length, deflated.length,
                (deflated.length * 100) / Math.max(1, data.length));
        return new CompressedBlob(deflated, data.length, true);
    }

    /**
     * Resolves a path to a (possibly cached) compressed blob on disk.
     * For static files (DLL beta, mappings) we cache the .z next to the
     * source and invalidate on mtime change — repeat downloads then skip
     * the DEFLATE pass entirely.
     */
    public CompressedBlob loadCompressedFromPath(Path source) throws IOException {
        long sourceSize = Files.size(source);
        if (sourceSize < COMPRESSION_MIN_SIZE) {
            return new CompressedBlob(Files.readAllBytes(source), (int) sourceSize, false);
        }

        Path cache = source.resolveSibling(source.getFileName() + ".z");
        long sourceMtime = Files.getLastModifiedTime(source).toMillis();
        if (Files.exists(cache)) {
            long cacheMtime = Files.getLastModifiedTime(cache).toMillis();
            if (cacheMtime >= sourceMtime) {
                byte[] cached = Files.readAllBytes(cache);
                log.debug("Cache hit for {}: {} -> {} bytes", source, sourceSize, cached.length);
                return new CompressedBlob(cached, (int) sourceSize, true);
            }
            log.info("Cache stale for {} (source newer), regenerating", source);
        }

        byte[] raw = Files.readAllBytes(source);
        CompressedBlob blob = compressIfWorthwhile(raw);
        if (blob.compressed()) {
            try {
                Files.write(cache, blob.payload());
            } catch (IOException e) {
                log.warn("Failed to write compression cache {}: {}", cache, e.getMessage());
            }
        }
        return blob;
    }

    /** Build chunk meta over an already-prepared {@link CompressedBlob}. */
    public FileChunkMetaData prepareChunkMetaForBlob(String key, CompressedBlob blob) {
        int payloadSize = blob.payloadSize();
        int chunkCount = (payloadSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
        log.info("Prepared chunk meta for '{}': {} chunks, total={} bytes, payload={} bytes ({}compressed)",
                key, chunkCount, blob.originalSize(), payloadSize, blob.compressed() ? "" : "un");
        return FileChunkMetaData.create(key, blob.originalSize(), payloadSize,
                chunkCount, CHUNK_SIZE, blob.compressed());
    }
}