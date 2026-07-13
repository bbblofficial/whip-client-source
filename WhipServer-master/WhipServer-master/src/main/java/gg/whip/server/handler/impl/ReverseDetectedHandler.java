package gg.whip.server.handler.impl;

import gg.whip.server.data.ClientSession;
import gg.whip.server.data.RawPacket;
import gg.whip.server.data.ReverseDetectedData;
import gg.whip.server.handler.base.AbstractSecureHandler;
import gg.whip.server.network.protocol.*;
import gg.whip.server.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class ReverseDetectedHandler extends AbstractSecureHandler {

    // RE tool detection mask (mirrors sentinel_th32_scan hit_mask in the loader).
    private static final long CM_X64DBG    = 0x001L;
    private static final long CM_CE        = 0x002L;
    private static final long CM_FIDDLER   = 0x004L;
    private static final long CM_IDA       = 0x008L;
    private static final long CM_WIRESHARK = 0x010L;
    private static final long CM_CUTTER    = 0x020L;
    private static final long CM_OLLY      = 0x040L;
    private static final long CM_WINDBG    = 0x080L;
    private static final long CM_CHARLES   = 0x200L;
    private static final long CM_VS_ENV    = 0x400L; // Visual Studio / VS Code debug adapter actif dans le process

    private static final long FLAG_PEB_DEBUG     = 1L << 0;
    private static final long FLAG_NTGFLAG       = 1L << 1;
    private static final long FLAG_HEAP          = 1L << 2;
    private static final long FLAG_DBG_PORT      = 1L << 3;
    private static final long FLAG_DBG_FLAGS     = 1L << 4;
    private static final long FLAG_HWBP          = 1L << 5;
    private static final long FLAG_TIMING        = 1L << 6;
    private static final long FLAG_SYSCALL       = 1L << 7;
    private static final long FLAG_NTCLOSE       = 1L << 8;
    private static final long FLAG_RDTSC_DBL     = 1L << 9;
    private static final long FLAG_NTDLL_HOOKED  = 1L << 10;
    private static final long FLAG_PAGE_RWX      = 1L << 11;
    private static final long FLAG_TLS           = 1L << 12;
    private static final long FLAG_FAKE_HWBP     = 1L << 13;
    private static final long FLAG_ANTI_ATTACH   = 1L << 14;
    private static final long FLAG_FRIDA         = 1L << 15;
    private static final long FLAG_VEH_DECOY     = 1L << 16;
    private static final long FLAG_ETW_HOOK      = 1L << 17;
    private static final long FLAG_DISPATCHER_PATCHED = 1L << 31;

    private final CryptoService cryptoService;
    private final AntiReplayService antiReplayService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final BlacklistService blacklistService;
    private final DiscordWebhookService discordWebhook;
    private final PacketReader packetReader;
    private final PacketWriter packetWriter;
    private final PacketSender packetSender;

    @Override
    protected org.slf4j.Logger getLogger() { return log; }

    @Override
    protected CryptoService getCryptoService() { return cryptoService; }

    @Override
    protected AntiReplayService getAntiReplayService() { return antiReplayService; }

    @Override
    protected PacketWriter getPacketWriter() { return packetWriter; }

    @Override
    protected PacketSender getPacketSender() { return packetSender; }

    @Override
    protected AnomalyDetectionService getAnomalyDetectionService() { return anomalyDetectionService; }

    @Override
    protected UUID getSessionUuid(ClientSession session) {
        return session.getDbSession() != null ? session.getDbSession().getId() : null;
    }

    @Override
    public boolean requiresEncryption() { return true; }

    @Override
    public void handle(ClientSession clientSession, RawPacket packet) {
        if (!clientSession.isAuthenticated()) {
            log.warn("Reverse-detected report from unauthenticated session {}", clientSession.getRemoteAddress());
            clientSession.close();
            return;
        }
        super.handle(clientSession, packet);
    }

    // Score below this with zero observable hits = likely noise / false-positive.
    // Don't ban automatically; log a SOFT warning so admins can review.
    // A real attack nearly always flips at least one of the 12 observable facts
    // (PEB, timing, hardware BP, etc.) OR reaches a much higher score through
    // the correlation multiplier. 70 is chosen as 40% above the threshold (50)
    // and well below what a single confirmed check produces (~100+).
    private static final long SOFT_SCORE_THRESHOLD = 70L;

    // Pending reports waiting for 0x93 REVERSE_DETECTED_SCREENSHOTS.
    // Keyed by requestId; auto-removed after 2s timeout (sends without screenshots).
    record PendingReport(
        ClientSession session,
        ReverseDetectedData data,
        boolean banned,
        boolean isSoft,
        boolean isVsEnv,
        String layerDetail,
        ScheduledFuture<?> timeout
    ) {}

    static final ConcurrentHashMap<String, PendingReport> PENDING = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService SCHEDULER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "rd-screenshot-timeout");
        t.setDaemon(true);
        return t;
    });

    static PendingReport removePending(String requestId) {
        return PENDING.remove(requestId);
    }

    @Override
    protected void processDecrypted(ClientSession clientSession, byte[] decrypted) {
        try {
            ReverseDetectedData data = packetReader.readReverseDetected(decrypted);

            if (!antiReplayService.isTimestampValid(data.timestamp())) {
                log.warn("Invalid timestamp on reverse report from {}", clientSession.getRemoteAddress());
                anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.INVALID_TIMESTAMP);
                return;
            }

            if (!validateAuthToken(clientSession, data.requestId(), data.authHmac(),
                    data.timestamp(), (short) 0x90)) {
                clientSession.close();
                return;
            }

            String tools       = describeCheckMask(data.checkMask());
            String flagLayers  = describeFlags(data.flags());
            String layerDetail = parseLayerReport(data.report());

            // VS / environnement dev — informatif uniquement, pas de ban, pas de poids violation.
            // Condition : seul le bit CM_VS_ENV est positionné (aucun autre outil), zéro hit observable.
            if (isVsEnvOnlyAlert(data.checkMask(), data.checksHit())) {
                log.info("[RE-VS-ENV] Visual Studio / adaptateur debug détecté pour {} — user={} score={} exe={}",
                        clientSession.getRemoteAddress(),
                        clientSession.getUser() != null ? clientSession.getUser().getUsername() : "?",
                        data.score(),
                        data.executablePath());
                ScheduledFuture<?> vsTimeout = SCHEDULER.schedule(() -> {
                    if (PENDING.remove(data.requestId()) != null) {
                        sendVsEnvWebhook(clientSession, data, layerDetail, Collections.emptyList());
                        clientSession.close();
                    }
                }, 2, TimeUnit.SECONDS);
                PENDING.put(data.requestId(), new PendingReport(
                        clientSession, data, false, false, true, layerDetail, vsTimeout));
                return;
            }

            // Soft = score just above noise floor with zero observable debug facts.
            // Hard = confirmed debugger hit OR score high enough that noise alone
            // can't explain it.
            boolean isSoft = (data.checksHit() == 0 && data.score() < SOFT_SCORE_THRESHOLD);

            if (isSoft) {
                log.warn("[RE-SOFT] Possible false-positive for {} — user={} score={} hits={}/{} "
                        + "tools={} flags={} | layers: {}",
                        clientSession.getRemoteAddress(),
                        clientSession.getUser() != null ? clientSession.getUser().getUsername() : "?",
                        data.score(), data.checksHit(), data.checksRun(),
                        tools.isEmpty() ? "none" : tools,
                        flagLayers,
                        layerDetail);
            } else {
                log.warn("[RE-HARD] Reverse-engineering confirmed for {} — user={} score={} hits={}/{} "
                        + "tools={} flags={} | layers: {}",
                        clientSession.getRemoteAddress(),
                        clientSession.getUser() != null ? clientSession.getUser().getUsername() : "?",
                        data.score(), data.checksHit(), data.checksRun(),
                        tools.isEmpty() ? "none" : tools,
                        flagLayers,
                        layerDetail);
            }

            anomalyDetectionService.recordViolation(clientSession.getIp(), ViolationType.REVERSE_DETECTED);

            boolean banned = false;
            if (!isSoft && clientSession.getUser() != null
                    && !blacklistService.isBlacklisted(clientSession.getUser())) {
                try {
                    String reason = tools.isEmpty()
                            ? "Reverse engineering detected — score=" + data.score() + " layers=" + flagLayers
                            : "Reverse engineering detected — tools=" + tools + " score=" + data.score();
                    blacklistService.blacklist(clientSession.getUser(), reason, null, "reverse-detector");
                    banned = true;
                } catch (Exception banEx) {
                    log.error("Failed to blacklist user {} after reverse detection",
                            clientSession.getUser().getUsername(), banEx);
                }
            }

            // Ne pas fermer immédiatement : attendre 0x93 avec les screenshots (2s max).
            final boolean wasBanned = banned;
            ScheduledFuture<?> timeout = SCHEDULER.schedule(() -> {
                if (PENDING.remove(data.requestId()) != null) {
                    sendReverseWebhook(clientSession, data, wasBanned, isSoft, layerDetail, Collections.emptyList());
                    clientSession.close();
                }
            }, 2, TimeUnit.SECONDS);
            PENDING.put(data.requestId(), new PendingReport(clientSession, data, wasBanned, isSoft, false, layerDetail, timeout));

        } catch (Exception e) {
            log.error("Error processing reverse-detected report from {}", clientSession.getRemoteAddress(), e);
        }
    }

    private static boolean isVsEnvOnlyAlert(long checkMask, long checksHit) {
        return (checkMask & CM_VS_ENV) != 0
            && (checkMask & ~CM_VS_ENV) == 0
            && checksHit == 0;
    }

    void sendVsEnvWebhook(ClientSession clientSession, ReverseDetectedData data,
                          String layerDetail, List<byte[]> screenshots) {
        Map<String, String> fields = new LinkedHashMap<>();

        if (clientSession.getUser() != null) {
            fields.put("Pseudo", clientSession.getUser().getUsername());
            fields.put("UUID", clientSession.getUser().getId().toString());
            if (clientSession.getUser().getDiscordId() != null) {
                fields.put("Discord", "<@" + clientSession.getUser().getDiscordId() + ">");
            }
        }

        if (clientSession.getMcUsername() != null && !clientSession.getMcUsername().isBlank()) {
            fields.put("MC Username", clientSession.getMcUsername());
        }

        fields.put("IP", clientSession.getRemoteAddress());

        if (clientSession.getMachine() != null && clientSession.getMachine().getHwid() != null) {
            fields.put("HWID", clientSession.getMachine().getHwid());
        }

        if (data.executablePath() != null && !data.executablePath().isBlank()) {
            fields.put("Executable", truncate(data.executablePath(), 200));
        }

        if (clientSession.getLicense() != null) {
            fields.put("Produit", clientSession.getLicense().getProduct().getName());
        }

        fields.put("Score", String.valueOf(data.score()));
        fields.put("Layers détail", truncate(layerDetail, 256));
        fields.put("Sanction", "ℹ️ Aucune — environnement de développement");

        discordWebhook.sendReverse(
                "🔵 Visual Studio détecté",
                "**L’adaptateur de débogage Visual Studio est actif sur la machine.**\n" +
                "Aucune action automatique — IDE de développement détecté.",
                0x5865F2,
                fields,
                screenshots
        );
    }

    // Parse the compact "key=val key=val …" layer report from the loader.
    // Returns a formatted string or "(no detail)" if the report is absent/old client.
    private String parseLayerReport(String raw) {
        if (raw == null || raw.isBlank() || raw.equals("?")) return "(no detail — old client)";
        // Re-format for readability: replace spaces with " | " between groups
        // corr/deep/cross/patch/exotic/adv/extra/poison vs hits + individual flags
        int hitsIdx = raw.indexOf("hits=");
        if (hitsIdx <= 0) return raw;
        String scores = raw.substring(0, hitsIdx).trim();
        String flags  = raw.substring(hitsIdx).trim();
        return "scores[" + scores + "] flags[" + flags + "]";
    }

    void sendReverseWebhook(ClientSession clientSession, ReverseDetectedData data,
                                     boolean banned, boolean isSoft, String layerDetail,
                                     List<byte[]> screenshots) {
        Map<String, String> fields = new LinkedHashMap<>();

        if (clientSession.getUser() != null) {
            fields.put("Pseudo", clientSession.getUser().getUsername());
            fields.put("UUID", clientSession.getUser().getId().toString());
            if (clientSession.getUser().getDiscordId() != null) {
                fields.put("Discord", "<@" + clientSession.getUser().getDiscordId() + ">");
            }
        }

        if (clientSession.getMcUsername() != null && !clientSession.getMcUsername().isBlank()) {
            fields.put("MC Username", clientSession.getMcUsername());
        }

        fields.put("IP", clientSession.getRemoteAddress());

        if (clientSession.getMachine() != null) {
            fields.put("HWID", clientSession.getMachine().getHwid());
            if (clientSession.getMachine().getPcName() != null) {
                fields.put("Nom du PC", clientSession.getMachine().getPcName());
            }
        }

        if (data.pcName() != null && !data.pcName().isBlank()) {
            fields.put("PC (live)", data.pcName());
        }

        if (data.executablePath() != null && !data.executablePath().isBlank()) {
            fields.put("Executable", truncate(data.executablePath(), 200));
        }

        if (clientSession.getLicense() != null) {
            fields.put("Produit", clientSession.getLicense().getProduct().getName());
        }

        fields.put("Score", data.score() + (isSoft ? " \u26A0\uFE0F (bruit probable)" : ""));
        fields.put("Hits", data.checksHit() + "/" + data.checksRun());

        String tools = describeCheckMask(data.checkMask());
        if (!tools.isEmpty()) fields.put("Outils detectes", tools);

        String flagLayers = describeFlags(data.flags());
        if (!flagLayers.equals("(none)")) fields.put("Layers anti-debug", flagLayers);

        // Layer breakdown \u2014 always include so admins see exactly what scored
        fields.put("Layers detail", truncate(layerDetail, 512));

        if (isSoft) {
            fields.put("Sanction", "\u26A0\uFE0F Aucune \u2014 score marginal (FP probable, v\u00E9rifier manuellement)");
        } else {
            fields.put("Sanction", banned ? "\uD83D\uDD28 Utilisateur ban (permanent)" : "Aucune (deja ban ou user inconnu)");
        }

        String title       = isSoft ? "\u26A0\uFE0F RE Soft Detection (noise)" : "\uD83D\uDD75\uFE0F Reverse Engineering Detected";
        int    color       = isSoft ? DiscordWebhookService.COLOR_ORANGE : DiscordWebhookService.COLOR_RED;
        String description = isSoft
                ? "**Score marginal d\u00E9tect\u00E9 \u2014 probable faux positif**\nV\u00E9rifier si la machine est sous charge ou utilise Hyper-V / VBS."
                : "**Tentative de reverse engineering confirm\u00E9e**";

        discordWebhook.sendReverse(title, description, color, fields, screenshots);
    }

    private String describeCheckMask(long mask) {
        if (mask == 0) return "";
        StringBuilder sb = new StringBuilder();
        appendFlag(sb, mask, CM_WIRESHARK, "Wireshark");
        appendFlag(sb, mask, CM_X64DBG,    "x64dbg");
        appendFlag(sb, mask, CM_CE,        "CheatEngine");
        appendFlag(sb, mask, CM_IDA,       "IDA");
        appendFlag(sb, mask, CM_FIDDLER,   "Fiddler");
        appendFlag(sb, mask, CM_OLLY,      "OllyDbg");
        appendFlag(sb, mask, CM_WINDBG,    "WinDbg");
        appendFlag(sb, mask, CM_CUTTER,    "Cutter");
        appendFlag(sb, mask, CM_CHARLES,   "Charles");
        appendFlag(sb, mask, CM_VS_ENV,    "VisualStudio");
        return sb.length() == 0 ? ("0x" + Long.toHexString(mask)) : sb.toString();
    }

    private String describeFlags(long flags) {
        if (flags == 0) return "(none)";
        StringBuilder sb = new StringBuilder();
        appendFlag(sb, flags, FLAG_DISPATCHER_PATCHED, "DISPATCHER_PATCHED");
        appendFlag(sb, flags, FLAG_PEB_DEBUG, "PEB.BeingDebugged");
        appendFlag(sb, flags, FLAG_NTGFLAG, "NtGlobalFlag");
        appendFlag(sb, flags, FLAG_HEAP, "HeapFlags");
        appendFlag(sb, flags, FLAG_DBG_PORT, "DebugPort");
        appendFlag(sb, flags, FLAG_DBG_FLAGS, "DebugFlags");
        appendFlag(sb, flags, FLAG_HWBP, "HWBP");
        appendFlag(sb, flags, FLAG_TIMING, "RDTSC_TIMING");
        appendFlag(sb, flags, FLAG_SYSCALL, "SYSCALL_TIMING");
        appendFlag(sb, flags, FLAG_NTCLOSE, "NtClose");
        appendFlag(sb, flags, FLAG_RDTSC_DBL, "RDTSC_DOUBLE");
        appendFlag(sb, flags, FLAG_NTDLL_HOOKED, "NTDLL_HOOKED");
        appendFlag(sb, flags, FLAG_PAGE_RWX, "PAGE_RWX");
        appendFlag(sb, flags, FLAG_TLS, "TLS_CALLBACK");
        appendFlag(sb, flags, FLAG_FAKE_HWBP, "FAKE_HWBP");
        appendFlag(sb, flags, FLAG_ANTI_ATTACH, "ANTI_ATTACH");
        appendFlag(sb, flags, FLAG_FRIDA, "FRIDA");
        appendFlag(sb, flags, FLAG_VEH_DECOY, "VEH_DECOY");
        appendFlag(sb, flags, FLAG_ETW_HOOK, "ETW_HOOK");
        return sb.length() == 0 ? ("0x" + Long.toHexString(flags)) : sb.toString();
    }

    private void appendFlag(StringBuilder sb, long value, long flag, String name) {
        if ((value & flag) == 0) return;
        if (sb.length() > 0) sb.append(", ");
        sb.append(name);
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    @Override
    protected void onNonceReplay(ClientSession session) {
        session.getChannel().close();
    }

    @Override
    protected void onHmacFailed(ClientSession session) {
        session.getChannel().close();
    }

    @Override
    protected void onDecryptionFailed(ClientSession session) {
        session.getChannel().close();
    }
}
