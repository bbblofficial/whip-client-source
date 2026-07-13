package gg.whip.server.data;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Registry of all downloadable files served by the bucket.
 *
 * <p>Each file has a {@link DownloadMode} that determines how it is delivered:
 * <ul>
 *   <li>{@link DownloadMode#SEQUENTIAL} — pushed to the loader in order via FILE_REQUEST (0x20).
 *       The server controls the sequence; the client key is ignored (zero-trust).</li>
 *   <li>{@link DownloadMode#ON_DEMAND} — pulled by the injected client via KEYED_FILE_REQUEST (0x22).
 *       The client specifies the key; the server validates it against the product's authorized set.</li>
 * </ul>
 *
 * <p>Dynamic files (e.g. {@code mappings-v1_8-lunar}) are not in this enum;
 */
@Getter
@RequiredArgsConstructor
public enum DownloadableFile {

    BETA_DLL("beta-dll", "/bucket/module/whip-client/beta/whip.dll", DownloadMode.SEQUENTIAL),
    VERSIONS("versions", "/bucket/versions/versions.json", DownloadMode.ON_DEMAND),
    /** Bypass DLL — WhipLoader built with WHIP_BYPASS_MODE=ON, manual-mapped into the host. */
    BYPASS_DLL("bypass-dll", "/bucket/module/whip-bypass/whiploader.dll", DownloadMode.SEQUENTIAL),
    ;

    private final String key;
    private final String bucketPath;
    private final DownloadMode mode;

    private static final Map<String, DownloadableFile> BY_KEY = new HashMap<>();

    static {
        for (DownloadableFile file : values()) {
            BY_KEY.put(file.key, file);
        }
    }

    public static DownloadableFile fromKey(String key) {
        return BY_KEY.get(key);
    }

    public static Set<String> allKeys() {
        return Set.copyOf(BY_KEY.keySet());
    }

    public enum DownloadMode {
        /** Loader downloads in fixed order via FILE_REQUEST (0x20). */
        SEQUENTIAL,
        /** Client downloads on-demand via KEYED_FILE_REQUEST (0x22). */
        ON_DEMAND
    }
}