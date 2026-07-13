package gg.whip.server.data;

import lombok.Getter;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;


@Getter
public enum Product {

    // TODO THIS SHIT !!
    WHIP_BETA(
            Set.of("WHIP_BETA", "WHIP_CLIENT", "beta"),
            List.of(DownloadableFile.BETA_DLL),
            List.of(DownloadableFile.VERSIONS)
    ),
    WHIP_BYPASS(
            Set.of("WHIP_BYPASS", "bypass"),
            List.of(DownloadableFile.BYPASS_DLL),
            List.of()
    );

    private static final Pattern DYNAMIC_MAPPINGS_PATTERN =
            Pattern.compile("^mappings-v[0-9_]+-[a-z]+$");

    private final Set<String> codes;
    private final List<DownloadableFile> loaderFiles;
    private final List<DownloadableFile> clientFiles;

    Product(Set<String> codes,
            List<DownloadableFile> loaderFiles,
            List<DownloadableFile> clientFiles) {
        this.codes = codes;
        this.loaderFiles = loaderFiles;
        this.clientFiles = clientFiles;
    }

    public static Product fromCode(String code) {
        if (code == null || code.isEmpty()) return null;
        for (Product product : values()) {
            for (String c : product.codes) {
                if (c.equalsIgnoreCase(code)) return product;
            }
        }
        return null;
    }

    public List<String> getLoaderDownloadSequence() {
        return loaderFiles.stream()
                .map(DownloadableFile::getKey)
                .toList();
    }

    public boolean isKeyAuthorized(String key) {
        if (key == null || key.isEmpty()) return false;

        for (DownloadableFile file : loaderFiles) {
            if (file.getKey().equals(key)) return true;
        }
        for (DownloadableFile file : clientFiles) {
            if (file.getKey().equals(key)) return true;
        }

        return DYNAMIC_MAPPINGS_PATTERN.matcher(key).matches();
    }
}