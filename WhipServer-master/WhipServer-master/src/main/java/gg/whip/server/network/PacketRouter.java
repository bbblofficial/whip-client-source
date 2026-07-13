package gg.whip.server.network;

import gg.whip.server.data.ClientSession;
import gg.whip.server.data.RawPacket;
import gg.whip.server.handler.impl.*;
import gg.whip.server.handler.IPacketHandler;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketType;
import gg.whip.server.network.protocol.PacketWriter;
import gg.whip.server.service.AnomalyDetectionService;
import gg.whip.server.service.AuditService;
import gg.whip.server.service.DiscordWebhookService;
import gg.whip.server.service.ThreatProfile;
import gg.whip.server.service.ViolationType;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class PacketRouter {

    private static final Logger log = LoggerFactory.getLogger(PacketRouter.class);

    private final RateLimiterHandler rateLimiter;
    private final AnomalyDetectionService anomalyDetectionService;
    private final DiscordWebhookService discordWebhook;
    private final PacketSender packetSender;
    private final PacketWriter packetWriter;
    private final HandshakeHandler handshakeHandler;
    private final HeartbeatHandler heartbeatHandler;
    private final InitHandler initHandler;
    private final ProductSelectHandler productSelectHandler;
    private final ClientAuthHandler clientAuthHandler;
    private final FileDownloadHandler fileDownloadHandler;
    private final KeyedFileDownloadHandler keyedFileDownloadHandler;
    private final MachineInfoHandler machineInfoHandler;
    private final ConfigHandler configHandler;
    private final ReverseDetectedHandler reverseDetectedHandler;
    private final ReverseDetectedScreenshotsHandler reverseDetectedScreenshotsHandler;
    private final SettingMutateHandler settingMutateHandler;
    private final ConnectFailReportHandler connectFailReportHandler;
    private final AuditService auditService;

    // Packets logged step-by-step into the audit journal (auth flow + downloads).
    private static final Set<PacketType> AUDIT_LOG_PACKETS = Set.of(
            PacketType.CLIENT_HELLO, PacketType.INIT_REQUEST, PacketType.PRODUCT_SELECT,
            PacketType.CLIENT_AUTH, PacketType.FILE_REQUEST, PacketType.KEYED_FILE_REQUEST
    );

    private static final Set<PacketType> AUTH_PACKETS = Set.of(
            PacketType.INIT_REQUEST, PacketType.PRODUCT_SELECT, PacketType.CLIENT_AUTH
    );

    private final Map<PacketType, IPacketHandler> handlers = new EnumMap<>(PacketType.class);

    @PostConstruct
    void init() {
        handlers.put(PacketType.CLIENT_HELLO, handshakeHandler);
        handlers.put(PacketType.HEARTBEAT, heartbeatHandler);
        handlers.put(PacketType.INIT_REQUEST, initHandler);
        handlers.put(PacketType.PRODUCT_SELECT, productSelectHandler);
        handlers.put(PacketType.CLIENT_AUTH, clientAuthHandler);
        handlers.put(PacketType.FILE_REQUEST, fileDownloadHandler);
        handlers.put(PacketType.KEYED_FILE_REQUEST, keyedFileDownloadHandler);
        handlers.put(PacketType.MACHINE_INFO, machineInfoHandler);
        handlers.put(PacketType.CONFIG_REQUEST, configHandler);
        handlers.put(PacketType.REVERSE_DETECTED, reverseDetectedHandler);
        handlers.put(PacketType.REVERSE_DETECTED_SCREENSHOTS, reverseDetectedScreenshotsHandler);
        handlers.put(PacketType.SETTING_MUTATE_REQUEST, settingMutateHandler);
        handlers.put(PacketType.CONNECT_FAIL_REPORT, connectFailReportHandler);
    }

    public void route(ClientSession session, RawPacket packet) {
        if (anomalyDetectionService.isBlocked(session.getIp())) {
            log.warn("Blocked IP attempted connection: {}", session.getIp());
            session.close();
            return;
        }

        // Check for active suspicious patterns — force disconnect on escalation
        var patterns = anomalyDetectionService.getActivePatterns(session.getIp());
        if (patterns.contains(ThreatProfile.SuspiciousPattern.ESCALATION)) {
            log.error("ESCALATION pattern detected for {} — disconnecting", session.getIp());
            discordWebhook.sendPattern("\uD83D\uDEA8 ESCALATION", "Escalation pattern detected — force disconnect",
                    DiscordWebhookService.COLOR_RED,
                    Map.of("IP", session.getIp(), "Patterns", patterns.toString()));
            session.close();
            return;
        }

        if (!rateLimiter.isRequestAllowed(session.getIp())) {
            log.warn("Rate limit exceeded for IP: {}", session.getIp());
            sendError(session, 429, "Rate limit exceeded");
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.RATE_LIMIT_EXCEEDED);
            discordWebhook.sendAnomaly("\u26A0\uFE0F Rate Limited", "Rate limit exceeded",
                    DiscordWebhookService.COLOR_ORANGE, Map.of("IP", session.getIp()));
            return;
        }

        if (AUTH_PACKETS.contains(packet.type()) && !rateLimiter.isAuthAllowed(session.getIp())) {
            log.warn("Auth rate limit exceeded for IP: {}", session.getIp());
            sendError(session, 429, "Auth rate limit exceeded");
            anomalyDetectionService.recordViolation(session.getIp(), ViolationType.RATE_LIMIT_EXCEEDED);
            return;
        }

        auditPacket(session, packet.type());

        IPacketHandler handler = handlers.get(packet.type());
        if (handler != null) {
            handler.handle(session, packet);
            return;
        }

        switch (packet.type()) {
            case DISCONNECT -> handleDisconnect(session);
            default -> log.warn("Unhandled packet type: {}", packet.type());
        }
    }

    /** Log each auth step + download request, attributed to the user when known. */
    private void auditPacket(ClientSession session, PacketType type) {
        if (!AUDIT_LOG_PACKETS.contains(type)) return;
        UUID uid = session.getUser() != null ? session.getUser().getId() : null;
        String user = session.getUser() != null ? session.getUser().getUsername() : "?";
        boolean download = type == PacketType.FILE_REQUEST || type == PacketType.KEYED_FILE_REQUEST;
        String action = switch (type) {
            case CLIENT_HELLO -> "auth.hello";
            case INIT_REQUEST -> "auth.init";
            case PRODUCT_SELECT -> "auth.product_select";
            case CLIENT_AUTH -> "auth.client_auth";
            case FILE_REQUEST -> "download.request";
            case KEYED_FILE_REQUEST -> "download.keyed_request";
            default -> "packet";
        };
        auditService.event(action, download ? "download" : "auth", uid, session.getIp(),
                type.name() + " — user=" + user + " ip=" + session.getRemoteAddress());
    }

    private void handleDisconnect(ClientSession session) {
        log.debug("Disconnect from {}", session.getRemoteAddress());
        session.setState(ClientSession.SessionState.DISCONNECTED);
        session.close();
    }

    private void sendError(ClientSession session, int code, String message) {
        byte[] payload = packetWriter.writeError(code, message);
        packetSender.send(session, PacketType.ERROR, payload);
    }
}
