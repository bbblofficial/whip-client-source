package gg.whip.server.handler.impl;

import gg.whip.server.network.PacketRouter;
import gg.whip.server.data.RawPacket;
import gg.whip.server.data.ClientSession;
import gg.whip.server.service.AnomalyDetectionService;
import gg.whip.server.service.AuditService;
import gg.whip.server.service.ConnectionPoolService;
import gg.whip.server.service.DiscordWebhookService;
import gg.whip.server.service.SessionService;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.util.AttributeKey;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@ChannelHandler.Sharable
@RequiredArgsConstructor
public class WhipServerHandler extends SimpleChannelInboundHandler<RawPacket> {

    private static final Logger log = LoggerFactory.getLogger(WhipServerHandler.class);
    private static final AttributeKey<ClientSession> SESSION_KEY = AttributeKey.valueOf("session");

    private final PacketRouter packetRouter;
    private final SessionService sessionService;
    private final ConnectionPoolService connectionPool;
    private final DiscordWebhookService discordWebhook;
    private final AnomalyDetectionService anomalyDetectionService;
    private final AuditService auditService;
    private final ApplicationContext applicationContext;

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        ClientSession session = new ClientSession(ctx.channel());

        // Check if IP is blocked by anomaly detection (in-memory)
        if (anomalyDetectionService.isBlocked(session.getIp())) {
            log.warn("Rejected connection from blocked IP: {}", session.getIp());
            discordWebhook.sendFail("🚫 Connexion bloquée",
                    "IP bloquée par l'anomaly detection",
                    DiscordWebhookService.COLOR_RED,
                    Map.of("IP", session.getRemoteAddress()));
            auditService.event("client.rejected", "connection", null, session.getIp(),
                    "IP bloquée (anomaly) " + session.getRemoteAddress());
            ctx.close();
            return;
        }

        if (!connectionPool.tryAdd(ctx.channel(), session.getIp())) {
            log.warn("Connection rejected for {} — pool limit reached", session.getIp());
            discordWebhook.sendFail("⚠️ Pool saturé",
                    "Connexion rejetée — limite de connexions atteinte",
                    DiscordWebhookService.COLOR_ORANGE,
                    Map.of("IP", session.getRemoteAddress(),
                           "Pool", connectionPool.getActiveCount() + " connexions actives"));
            auditService.event("client.rejected", "connection", null, session.getIp(),
                    "Pool saturé " + session.getRemoteAddress());
            ctx.close();
            return;
        }

        ctx.channel().attr(SESSION_KEY).set(session);
        log.debug("Client connected: {} — pool: {}", session.getRemoteAddress(), connectionPool.getActiveCount());

        discordWebhook.sendConnect("\uD83D\uDD0C Connection", "New client connected",
                DiscordWebhookService.COLOR_GREEN,
                Map.of("IP", session.getRemoteAddress()));
        auditService.event("client.connect", "connection", null, session.getIp(),
                "Connexion " + session.getRemoteAddress());
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        ClientSession session = ctx.channel().attr(SESSION_KEY).get();
        if (session != null) {
            connectionPool.remove(ctx.channel(), session.getIp());
            session.setState(ClientSession.SessionState.DISCONNECTED);
            if (session.getDbSession() != null && isContextActive()) {
                try {
                    sessionService.end(session.getDbSession());
                } catch (Exception e) {
                    log.warn("Failed to end session for {}: {}", session.getRemoteAddress(), e.getMessage());
                }
            }
            String username = session.getUser() != null ? session.getUser().getUsername() : "";
            log.debug("Client disconnected: {} {} — pool: {}", session.getRemoteAddress(), username, connectionPool.getActiveCount());

            Map<String, String> fields = new LinkedHashMap<>();
            if (!username.isEmpty()) fields.put("Pseudo", username);
            if (session.getUser() != null) {
                fields.put("UUID", session.getUser().getId().toString());
            }
            if (session.getMcUsername() != null && !session.getMcUsername().isBlank()) {
                fields.put("MC Username", session.getMcUsername());
            }
            fields.put("IP", session.getRemoteAddress());
            if (session.getMachine() != null) {
                fields.put("HWID", session.getMachine().getHwid());
                if (session.getMachine().getPcName() != null) {
                    fields.put("Nom du PC", session.getMachine().getPcName());
                }
            }
            if (session.getUser() != null && session.getUser().getDiscordId() != null) {
                fields.put("Discord", "<@" + session.getUser().getDiscordId() + ">");
            }
            if (session.getLicense() != null) {
                fields.put("Produit", session.getLicense().getProduct().getName());
                fields.put("Expiration", session.getLicense().getExpiresAt() != null
                        ? session.getLicense().getExpiresAt().toString() : "Lifetime");
            }
            if (session.getDbSession() != null && session.getDbSession().getStartedAt() != null) {
                Duration duration = Duration.between(session.getDbSession().getStartedAt(), Instant.now());
                long hours = duration.toHours();
                long minutes = duration.toMinutesPart();
                long seconds = duration.toSecondsPart();
                fields.put("Durée", hours > 0
                        ? String.format("%dh %dm %ds", hours, minutes, seconds)
                        : minutes > 0
                                ? String.format("%dm %ds", minutes, seconds)
                                : String.format("%ds", seconds));
            }
            discordWebhook.sendDisconnect("\uD83D\uDD34 Disconnection", "Client disconnected",
                    DiscordWebhookService.COLOR_ORANGE, fields);
            java.util.UUID disconnectUid = session.getUser() != null ? session.getUser().getId() : null;
            auditService.event("client.disconnect", "connection", disconnectUid, session.getIp(),
                    (username.isEmpty() ? "" : username + " — ") + "IP " + session.getRemoteAddress());
        }
    }

    private boolean isContextActive() {
        return applicationContext instanceof ConfigurableApplicationContext cac && cac.isActive();
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, RawPacket packet) {
        ClientSession session = ctx.channel().attr(SESSION_KEY).get();
        if (session == null) {
            ctx.close();
            return;
        }

        try {
            packetRouter.route(session, packet);
        } catch (Exception e) {
            log.error("Error processing packet from {} (type={}, state={}, user={}): {}",
                    session.getRemoteAddress(),
                    packet != null && packet.type() != null ? packet.type().name() : "null",
                    session.getState(),
                    session.getUser() != null ? session.getUser().getUsername() : "anonymous",
                    e.getMessage(),
                    e);
            ctx.close();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ClientSession session = ctx.channel().attr(SESSION_KEY).get();
        String address = session != null ? session.getRemoteAddress() : "unknown";

        // Expected disconnects (TCP RST, broken pipe, idle timeout) are not errors \u2014
        // the client just closed the connection or the OS dropped it. Log at DEBUG only.
        if (isExpectedDisconnect(cause)) {
            log.debug("Abrupt disconnect from {}: {}", address, cause.getMessage());
            ctx.close();
            return;
        }

        log.error("Exception from {}: {}", address, cause.getMessage(), cause);
        discordWebhook.sendFail("\u26A0\uFE0F Exception", cause.getMessage(),
                DiscordWebhookService.COLOR_RED,
                Map.of("IP", address));
        auditService.event("server.error", "server", null,
                session != null ? session.getIp() : null,
                (cause.getClass().getSimpleName()) + ": " + cause.getMessage() + " [" + address + "]");
        ctx.close();
    }

    private static boolean isExpectedDisconnect(Throwable cause) {
        if (!(cause instanceof java.io.IOException)) return false;
        String msg = cause.getMessage();
        if (msg == null) return true;
        String lower = msg.toLowerCase();
        return lower.contains("connection reset")
            || lower.contains("broken pipe")
            || lower.contains("connection timed out")
            || lower.contains("forcibly closed")
            || lower.contains("connexion ") // French JVM messages
            || lower.contains("remote host");
    }
}
