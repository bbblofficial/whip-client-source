package gg.whip.server.service;

import gg.whip.server.config.ServerProperties;
import gg.whip.server.data.ClientSession;
import gg.whip.server.network.protocol.PacketSender;
import gg.whip.server.network.protocol.PacketType;
import io.netty.channel.Channel;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.GlobalEventExecutor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
@RequiredArgsConstructor
public class ConnectionPoolService {

    private static final Logger log = LoggerFactory.getLogger(ConnectionPoolService.class);

    private final ServerProperties serverProperties;
    private final PacketSender packetSender;

    private final ChannelGroup channels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
    private final ConcurrentHashMap<String, Set<Channel>> ipChannels = new ConcurrentHashMap<>();
    private final AtomicInteger activeCount = new AtomicInteger(0);

    private final Object poolLock = new Object();

    public boolean tryAdd(Channel channel, String ip) {
        int maxConnections = serverProperties.getPool().getMaxConnections();
        int maxPerIp = serverProperties.getPool().getMaxPerIp();

        synchronized (poolLock) {
            if (activeCount.get() >= maxConnections) {
                log.warn("Connection pool full ({}/{}), rejecting {}", activeCount.get(), maxConnections, ip);
                return false;
            }

            Set<Channel> perIp = ipChannels.computeIfAbsent(ip, k -> ConcurrentHashMap.newKeySet());
            if (perIp.size() >= maxPerIp) {
                log.warn("Per-IP limit reached ({}/{}) for {}, rejecting", perIp.size(), maxPerIp, ip);
                return false;
            }

            channels.add(channel);
            perIp.add(channel);
            activeCount.incrementAndGet();
        }

        log.debug("Connection added for {} — pool: {}/{}, ip: {}/{}", ip, activeCount.get(), maxConnections,
                ipChannels.getOrDefault(ip, Set.of()).size(), maxPerIp);
        return true;
    }

    public void remove(Channel channel, String ip) {
        synchronized (poolLock) {
            channels.remove(channel);
            Set<Channel> perIp = ipChannels.get(ip);
            if (perIp != null) {
                perIp.remove(channel);
                if (perIp.isEmpty()) {
                    ipChannels.remove(ip);
                }
            }
            activeCount.decrementAndGet();
        }
        log.debug("Connection removed for {} — pool: {}", ip, activeCount.get());
    }

    public int getActiveCount() {
        return activeCount.get();
    }

    public int getCountForIp(String ip) {
        Set<Channel> perIp = ipChannels.get(ip);
        return perIp != null ? perIp.size() : 0;
    }

    public Set<Channel> getChannelsForIp(String ip) {
        return ipChannels.get(ip);
    }

    public void disconnectAll() {
        synchronized (poolLock) {
            int count = activeCount.get();
            log.info("Disconnecting all {} connections", count);
            channels.close();
            ipChannels.clear();
            activeCount.set(0);
        }
    }

    /** Channel attribute key used by WhipServerHandler to bind ClientSession. */
    private static final AttributeKey<ClientSession> SESSION_KEY = AttributeKey.valueOf("session");

    /**
     * Force-close the live Netty channel of the session with the given DB
     * session UUID. Returns true if a matching live channel was found and
     * closed. Used by SyncListener when an admin clicks "KICK" on
     * /admin/sessions.
     */
    public boolean disconnectBySessionId(UUID sessionId) {
        if (sessionId == null) return false;
        for (Channel ch : channels) {
            ClientSession cs = ch.attr(SESSION_KEY).get();
            if (cs == null) continue;
            if (cs.getDbSession() == null) continue;
            if (sessionId.equals(cs.getDbSession().getId())) {
                log.info("Admin-triggered close: session={} ip={}",
                        sessionId, cs.getRemoteAddress());
                ch.close();
                return true;
            }
        }
        return false;
    }

    /**
     * Find the live channel for {@code sessionId} and ship a SESSION_CRASH
     * packet. The WhipClient DLL handler responds by deliberately AVing
     * (writing to address 0) which kills the host game process.
     *
     * <p>The packet is sent in the clear — the DLL doesn't need to verify
     * authenticity beyond receiving it on its already-encrypted WhipNexus
     * channel. The channel is closed right after the write to drop the
     * connection cleanly.
     */
    /**
     * Kick every live channel owned by the given user. Used when an
     * admin updates the user's config — they reconnect on next heartbeat
     * and pull fresh config via CONFIG_REQUEST.
     */
    public int disconnectByUserId(UUID userId) {
        if (userId == null) return 0;
        int kicked = 0;
        for (Channel ch : channels) {
            ClientSession cs = ch.attr(SESSION_KEY).get();
            if (cs == null) continue;
            if (cs.getUser() == null) continue;
            if (userId.equals(cs.getUser().getId())) {
                ch.close();
                kicked++;
            }
        }
        return kicked;
    }

    public boolean crashBySessionId(UUID sessionId) {
        if (sessionId == null) return false;
        for (Channel ch : channels) {
            ClientSession cs = ch.attr(SESSION_KEY).get();
            if (cs == null) continue;
            if (cs.getDbSession() == null) continue;
            if (sessionId.equals(cs.getDbSession().getId())) {
                log.warn("Admin-triggered CRASH: session={} ip={} mc={}",
                        sessionId, cs.getRemoteAddress(),
                        cs.getMcUsername());
                // Encrypted send via the existing per-session AES-GCM
                // channel — the DLL won't trust an opcode arriving in
                // the clear. Empty payload; the opcode itself is the
                // command. The DLL handler decrypts, recognizes
                // SESSION_CRASH, deliberately AVs to take down the
                // host process.
                packetSender.sendEncrypted(cs, PacketType.SESSION_CRASH, new byte[0]);
                // Don't close the channel here — let the AV take down
                // the connection naturally. If the DLL never receives
                // the packet (channel buffered but read-side dead), the
                // existing heartbeat timeout will reap the session.
                return true;
            }
        }
        return false;
    }

    public int disconnectIp(String ip) {
        synchronized (poolLock) {
            Set<Channel> perIp = ipChannels.remove(ip);
            if (perIp != null) {
                int count = perIp.size();
                for (Channel ch : perIp) {
                    channels.remove(ch);
                    ch.close();
                    activeCount.decrementAndGet();
                }
                log.info("Disconnected {} connections for IP {}", count, ip);
                return count;
            }
            return 0;
        }
    }
}