package gg.whip.server;

import gg.whip.server.config.ServerProperties;
import gg.whip.server.handler.impl.WhipServerHandler;
import gg.whip.server.service.AuditService;
import gg.whip.server.service.ConnectionPoolService;
import gg.whip.server.network.codec.PacketDecoder;
import gg.whip.server.network.codec.PacketEncoder;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.timeout.IdleStateHandler;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class WhipServer {

    private static final Logger log = LoggerFactory.getLogger(WhipServer.class);

    private final ServerProperties serverProperties;
    private final WhipServerHandler serverHandler;
    private final ConnectionPoolService connectionPool;
    private final AuditService auditService;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private ChannelFuture serverChannel;
    private final java.util.concurrent.atomic.AtomicBoolean stopLogged = new java.util.concurrent.atomic.AtomicBoolean(false);

    @PostConstruct
    public void start() {
        new Thread(this::run, "netty-server").start();
    }

    private void run() {
        logDirectories();

        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();

        try {
            SslContext sslContext = buildSslContext();

            ServerBootstrap bootstrap = new ServerBootstrap()
                    .group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, true)
                    .childOption(ChannelOption.TCP_NODELAY, true)
                    .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK,
                            new WriteBufferWaterMark(32 * 1024, 64 * 1024))
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            if (sslContext != null) {
                                ch.pipeline().addLast(sslContext.newHandler(ch.alloc()));
                            }
                            ch.pipeline().addLast(
                                    new IdleStateHandler(120, 0, 0, TimeUnit.SECONDS),
                                    new PacketDecoder(),
                                    new PacketEncoder(),
                                    serverHandler
                            );
                        }
                    });

            serverChannel = bootstrap.bind(serverProperties.getPort()).sync();
            log.info("WhipServer started on port {}", serverProperties.getPort());
            auditService.system("server.start", "server",
                    "WhipServer démarré sur le port " + serverProperties.getPort());

            serverChannel.channel().closeFuture().sync();
        } catch (Exception e) {
            log.error("Failed to start server", e);
        } finally {
            shutdown();
        }
    }

    private void logDirectories() {
        log.info("═══════════════════════════════════════════════════════════════");
        log.info("Accessible directories:");

        ServerProperties.Tls tls = serverProperties.getTls();
        String certDir = tls.getCertificateDir() != null ? tls.getCertificateDir() : "./certs";
        logDirectory("  Certificates", certDir);

        String keystorePath = tls.getKeystorePath();
        if (keystorePath == null || keystorePath.isBlank()) {
            keystorePath = DEFAULT_TLS_CERT;
        }
        logDirectory("  TLS", new File(keystorePath).getParent());

        logDirectory("  Modules", serverProperties.getModules().getBasePath());
        log.info("═══════════════════════════════════════════════════════════════");
    }

    private void logDirectory(String label, String path) {
        if (path == null) return;
        File dir = new File(path);
        String status;
        if (!dir.exists()) {
            status = "MISSING";
        } else if (!dir.canWrite()) {
            status = "READ-ONLY";
        } else {
            String[] files = dir.list();
            int count = files != null ? files.length : 0;
            status = count + " file(s), writable";
        }
        log.info("{}: {} [{}]", label, dir.getAbsolutePath(), status);
    }

    private static final String DEFAULT_TLS_CERT = "/app/tls/server.crt";

    private SslContext buildSslContext() {
        try {
            ServerProperties.Tls tls = serverProperties.getTls();
            String keystorePath = tls.getKeystorePath();
            if (keystorePath == null || keystorePath.isBlank()) {
                keystorePath = DEFAULT_TLS_CERT;
            }

            File certFile = new File(keystorePath);
            if (!certFile.exists()) {
                log.warn("TLS not configured, running without encryption (cert not found: {})", keystorePath);
                return null;
            }

            File keyFile = new File(keystorePath.replace(".crt", ".key"));

            String password = tls.getKeystorePassword();
            return SslContextBuilder.forServer(certFile, keyFile, password).build();
        } catch (Exception e) {
            log.error("Failed to load SSL context", e);
            return null;
        }
    }

    @PreDestroy
    public void shutdown() {
        log.info("Shutting down WhipServer... ({} active connections)", connectionPool.getActiveCount());
        if (stopLogged.compareAndSet(false, true)) {
            auditService.systemSync("server.stop", "server", "Arrêt du serveur WhipServer");
        }
        connectionPool.disconnectAll();
        if (serverChannel != null) {
            serverChannel.channel().close();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
    }
}