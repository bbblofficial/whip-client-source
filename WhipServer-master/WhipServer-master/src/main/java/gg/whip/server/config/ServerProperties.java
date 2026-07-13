package gg.whip.server.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "server")
@Getter
@Setter
public class ServerProperties {

    private int port = 7777;
    private Tls tls = new Tls();
    private Session session = new Session();
    private Security security = new Security();
    private Modules modules = new Modules();
    private AnomalyDetection anomalyDetection = new AnomalyDetection();
    private Pool pool = new Pool();
    private Blacklist blacklist = new Blacklist();
    private Discord discord = new Discord();
    private Watermark watermark = new Watermark();

    @Getter
    @Setter
    public static class Tls {
        private String keystorePath;
        private String keystorePassword;
        private String certificateDir;
    }

    @Getter
    @Setter
    public static class Session {
        private int ttlMinutes = 15;
        private int heartbeatIntervalSeconds = 30;
        private int heartbeatTimeoutSeconds = 60;
        private int maxPerLicense = 1;
        private int maxPerMachine = 2;
        private long cleanupIntervalMs = 60000;
    }

    @Getter
    @Setter
    public static class Security {
        private int timestampToleranceSeconds = 30;
        private int requestIdRetentionMinutes = 5;
        private long cleanupIntervalMs = 300000;
    }

    @Getter
    @Setter
    public static class Modules {
        private String basePath = "modules";
    }

    @Getter
    @Setter
    public static class AnomalyDetection {
        private int blockThreshold = 100;
        private int windowSeconds = 300;
        private long cleanupIntervalMs = 60000;
    }

    @Getter
    @Setter
    public static class Pool {
        private int maxConnections = 500;
        private int maxPerIp = 10;
    }

    @Getter
    @Setter
    public static class Blacklist {
        private long cacheRefreshMs = 30000;
        private long cleanupIntervalMs = 3600000;
        private int autoBlockHours = 24;
    }

    @Getter
    @Setter
    public static class Watermark {
        /**
         * Server-side HMAC key for the per-download DLL watermark
         * (DUMP_THREAT_MODEL.md §5.3). Configure via env
         * {@code SERVER_WATERMARK_SECRET} — empty disables HMAC trunc
         * (uuid-only watermarks still work but can be forged into a
         * leaked dump to confuse attribution).
         */
        private String secret = "";
    }

    @Getter
    @Setter
    public static class Discord {
        private boolean enabled = false;
        private String connectWebhookUrl;
        private String disconnectWebhookUrl;
        private String successWebhookUrl;
        private String failWebhookUrl;
        private String anomalyWebhookUrl;
        private String patternWebhookUrl;
        private String reverseWebhookUrl;
    }
}
