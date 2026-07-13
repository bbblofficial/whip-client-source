package gg.whip.server.service;

import gg.whip.server.config.ServerProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@Service
@RequiredArgsConstructor
public class DiscordWebhookService {

    private static final Logger log = LoggerFactory.getLogger(DiscordWebhookService.class);

    public static final int COLOR_GREEN  = 0x2ECC71;
    public static final int COLOR_ORANGE = 0xF39C12;
    public static final int COLOR_RED    = 0xE74C3C;

    private final ServerProperties serverProperties;
    private HttpClient httpClient;

    @PostConstruct
    void init() {
        if (serverProperties.getDiscord().isEnabled()) {
            httpClient = HttpClient.newHttpClient();
            log.info("Discord webhook alerting enabled");
        }
    }

    public void sendConnect(String title, String description, int color, Map<String, String> fields) {
        send(serverProperties.getDiscord().getConnectWebhookUrl(), title, description, color, fields, null);
    }

    public void sendDisconnect(String title, String description, int color, Map<String, String> fields) {
        send(serverProperties.getDiscord().getDisconnectWebhookUrl(), title, description, color, fields, null);
    }

    public void sendSuccess(String title, String description, int color, Map<String, String> fields) {
        send(serverProperties.getDiscord().getSuccessWebhookUrl(), title, description, color, fields, null);
    }

    public void sendSuccess(String title, String description, int color, Map<String, String> fields, String thumbnailUrl) {
        send(serverProperties.getDiscord().getSuccessWebhookUrl(), title, description, color, fields, thumbnailUrl);
    }

    public void sendFail(String title, String description, int color, Map<String, String> fields) {
        send(serverProperties.getDiscord().getFailWebhookUrl(), title, description, color, fields, null);
    }

    public void sendAnomaly(String title, String description, int color, Map<String, String> fields) {
        send(serverProperties.getDiscord().getAnomalyWebhookUrl(), title, description, color, fields, null);
    }

    public void sendPattern(String title, String description, int color, Map<String, String> fields) {
        send(serverProperties.getDiscord().getPatternWebhookUrl(), title, description, color, fields, null);
    }

    public void sendReverse(String title, String description, int color, Map<String, String> fields) {
        sendReverse(title, description, color, fields, Collections.emptyList());
    }

    public void sendReverse(String title, String description, int color, Map<String, String> fields,
                             List<byte[]> screenshots) {
        String url = serverProperties.getDiscord().getReverseWebhookUrl();
        if (url == null || url.isBlank()) url = serverProperties.getDiscord().getAnomalyWebhookUrl();

        List<byte[]> shots = screenshots == null ? Collections.emptyList()
                : screenshots.stream().filter(s -> s != null && s.length > 0).toList();

        if (shots.isEmpty()) {
            send(url, "@everyone", title, description, color, fields, null);
            return;
        }

        // ── Message 1 : embed principal avec le premier écran ─────────────────
        String mainJson = buildJson("@everyone", title, description, color, fields, null,
                "attachment://screen0.jpg",
                "[{\"id\":0,\"filename\":\"screen0.jpg\"}]");

        CompletableFuture<Void> chain = sendMultipartFuture(url, mainJson,
                List.of(shots.get(0)), List.of("screen0.jpg"));

        // ── Messages suivants : un par moniteur supplémentaire ─────────────────
        final String finalUrl = url;
        for (int i = 1; i < shots.size(); i++) {
            final int idx   = i;
            final int total = shots.size();
            final byte[] shotBytes = shots.get(i);
            chain = chain.thenCompose(ignored -> {
                String followJson = buildScreenOnlyJson(idx + 1, total);
                return sendMultipartFuture(finalUrl, followJson,
                        List.of(shotBytes), List.of("screen0.jpg"));
            });
        }
    }

    // ─── private helpers ──────────────────────────────────────────────────────

    private void send(String webhookUrl, String title, String description, int color,
                      Map<String, String> fields, String thumbnailUrl) {
        send(webhookUrl, null, title, description, color, fields, thumbnailUrl);
    }

    private void send(String webhookUrl, String content, String title, String description, int color,
                      Map<String, String> fields, String thumbnailUrl) {
        if (!serverProperties.getDiscord().isEnabled()) return;
        if (webhookUrl == null || webhookUrl.isBlank()) return;

        String json = buildJson(content, title, description, color, fields, thumbnailUrl, null);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(webhookUrl))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .whenComplete((response, error) -> {
                    if (error != null) {
                        log.warn("Discord webhook send failed: {}", error.getMessage());
                    } else if (response.statusCode() >= 400) {
                        log.warn("Discord webhook returned {}: {}", response.statusCode(), response.body());
                    }
                });
    }

    /**
     * Sends a multipart webhook and returns a CompletableFuture<Void> for chaining.
     * {@code filenames} must have the same size as {@code files}.
     * Each file is referenced as {@code files[i]} with the matching filename.
     */
    private CompletableFuture<Void> sendMultipartFuture(String webhookUrl, String payloadJson,
                                                         List<byte[]> files, List<String> filenames) {
        if (!serverProperties.getDiscord().isEnabled())
            return CompletableFuture.completedFuture(null);
        if (webhookUrl == null || webhookUrl.isBlank())
            return CompletableFuture.completedFuture(null);

        String bnd  = "----WhipBoundary" + Long.toHexString(System.nanoTime());
        byte[] body = buildMultipartBodyWithBoundary(payloadJson, files, filenames, bnd);
        if (body == null) return CompletableFuture.completedFuture(null);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(webhookUrl))
                .header("Content-Type", "multipart/form-data; boundary=" + bnd)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .whenComplete((response, error) -> {
                    if (error != null) {
                        log.warn("Discord webhook (multipart) send failed: {}", error.getMessage());
                    } else if (response.statusCode() >= 400) {
                        log.warn("Discord webhook (multipart) returned {}: {}",
                                response.statusCode(), response.body());
                    }
                })
                .thenApply(r -> (Void) null);
    }

    private byte[] buildMultipartBodyWithBoundary(String payloadJson, List<byte[]> files,
                                                   List<String> filenames, String boundary) {
        byte[] crlf     = "\r\n".getBytes(StandardCharsets.UTF_8);
        byte[] dashDash = "--".getBytes(StandardCharsets.UTF_8);
        byte[] bndBytes = boundary.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        try {
            // payload_json part
            body.write(dashDash); body.write(bndBytes); body.write(crlf);
            body.write("Content-Disposition: form-data; name=\"payload_json\"\r\n"
                    .getBytes(StandardCharsets.UTF_8));
            body.write("Content-Type: application/json\r\n".getBytes(StandardCharsets.UTF_8));
            body.write(crlf);
            body.write(payloadJson.getBytes(StandardCharsets.UTF_8));
            body.write(crlf);

            // file parts
            for (int i = 0; i < files.size(); i++) {
                String fn = filenames.get(i);
                body.write(dashDash); body.write(bndBytes); body.write(crlf);
                body.write(("Content-Disposition: form-data; name=\"files[" + i + "]\"; filename=\""
                        + fn + "\"\r\n").getBytes(StandardCharsets.UTF_8));
                body.write("Content-Type: image/jpeg\r\n".getBytes(StandardCharsets.UTF_8));
                body.write(crlf);
                body.write(files.get(i));
                body.write(crlf);
            }

            // closing boundary
            body.write(dashDash); body.write(bndBytes); body.write(dashDash); body.write(crlf);
        } catch (IOException e) {
            log.warn("Failed to build multipart body: {}", e.getMessage());
            return null;
        }
        return body.toByteArray();
    }

    // ── JSON builders ─────────────────────────────────────────────────────────

    /** Minimal embed for a follow-up monitor screenshot (no fields, no mention). */
    private String buildScreenOnlyJson(int screenNumber, int total) {
        String filename  = "screen0.jpg";  // always file[0] in its own message
        String title     = "📸 Écran " + screenNumber + "/" + total;
        return "{\"embeds\":[{\"title\":\"" + escapeJson(title) + "\","
                + "\"color\":" + COLOR_RED + ","
                + "\"image\":{\"url\":\"attachment://" + filename + "\"},"
                + "\"timestamp\":\"" + Instant.now() + "\"}],"
                + "\"attachments\":[{\"id\":0,\"filename\":\"" + filename + "\"}]}";
    }

    private String buildJson(String title, String description, int color,
                              Map<String, String> fields, String thumbnailUrl, String imageUrl) {
        return buildJson(null, title, description, color, fields, thumbnailUrl, imageUrl, null);
    }

    private String buildJson(String content, String title, String description, int color,
                              Map<String, String> fields, String thumbnailUrl, String imageUrl) {
        return buildJson(content, title, description, color, fields, thumbnailUrl, imageUrl, null);
    }

    private String buildJson(String content, String title, String description, int color,
                              Map<String, String> fields, String thumbnailUrl, String imageUrl,
                              String attachmentsJsonArray) {
        StringBuilder fieldsJson = new StringBuilder();
        int i = 0;
        for (var entry : fields.entrySet()) {
            if (i > 0) fieldsJson.append(",");
            fieldsJson.append("{\"name\":\"")
                    .append(escapeJson(entry.getKey()))
                    .append("\",\"value\":\"")
                    .append(escapeJson(entry.getValue()))
                    .append("\",\"inline\":true}");
            i++;
        }

        String thumbnailJson = "";
        if (thumbnailUrl != null && !thumbnailUrl.isBlank())
            thumbnailJson = ",\"thumbnail\":{\"url\":\"" + escapeJson(thumbnailUrl) + "\"}";

        String imageJson = "";
        if (imageUrl != null && !imageUrl.isBlank())
            imageJson = ",\"image\":{\"url\":\"" + escapeJson(imageUrl) + "\"}";

        String attachmentsJson = "";
        if (attachmentsJsonArray != null && !attachmentsJsonArray.isBlank()) {
            attachmentsJson = ",\"attachments\":" + attachmentsJsonArray;
        } else if (imageUrl != null && imageUrl.startsWith("attachment://")) {
            String fn = imageUrl.substring("attachment://".length());
            attachmentsJson = ",\"attachments\":[{\"id\":0,\"filename\":\"" + escapeJson(fn) + "\"}]";
        }

        String contentJson = "";
        if (content != null && !content.isBlank())
            contentJson = "\"content\":\"" + escapeJson(content) + "\","
                        + "\"allowed_mentions\":{\"parse\":[\"everyone\"]},";

        return ("{" + contentJson + "\"embeds\":[{\"title\":\"%s\",\"description\":\"%s\",\"color\":%d"
                + ",\"fields\":[%s]%s%s,\"timestamp\":\"%s\",\"footer\":{\"text\":\"WhipServer\"}}]%s}")
                .formatted(
                        escapeJson(title),
                        escapeJson(description),
                        color,
                        fieldsJson.toString(),
                        thumbnailJson,
                        imageJson,
                        Instant.now().toString(),
                        attachmentsJson
                );
    }

    private static String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
