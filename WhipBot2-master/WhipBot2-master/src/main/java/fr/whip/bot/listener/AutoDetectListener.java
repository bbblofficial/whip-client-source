package fr.whip.bot.listener;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.impl.DetectCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import net.dv8tion.jda.api.entities.Guild;
import net.dv8tion.jda.api.events.channel.ChannelCreateEvent;
import net.dv8tion.jda.api.events.channel.ChannelDeleteEvent;
import net.dv8tion.jda.api.events.channel.update.ChannelUpdateNameEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Watches the guild's channel/category structure and re-runs the same
 * detection as {@code /detect} ({@link DetectCommand#runDetect}) whenever
 * channels are created, deleted or renamed — keeping the channel IDs saved in
 * config.yml in sync automatically. Runs silently (logs only, no Discord
 * reply). Rapid bursts of structural changes are debounced into a single
 * detection pass per guild.
 */
public class AutoDetectListener implements Listener {

    private static final Logger LOGGER = LoggerFactory.getLogger(AutoDetectListener.class);
    private static final long DEBOUNCE_SECONDS = 3;

    private final WhipBot main;
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "auto-detect");
                t.setDaemon(true);
                return t;
            });
    private final ConcurrentMap<String, ScheduledFuture<?>> pending = new ConcurrentHashMap<>();

    public AutoDetectListener(WhipBot main) {
        this.main = main;
    }

    @EventHandler
    public void onChannelCreate(ChannelCreateEvent event) {
        if (event.getChannelType().isGuild())
            scheduleDetect(event.getGuild());
    }

    @EventHandler
    public void onChannelDelete(ChannelDeleteEvent event) {
        if (event.getChannelType().isGuild())
            scheduleDetect(event.getGuild());
    }

    @EventHandler
    public void onChannelRename(ChannelUpdateNameEvent event) {
        if (event.getChannelType().isGuild())
            scheduleDetect(event.getGuild());
    }

    /** Debounced re-detection: coalesces rapid structural changes per guild. */
    private void scheduleDetect(Guild guild) {
        if (guild == null)
            return;
        String guildId = guild.getId();
        ScheduledFuture<?> previous = pending.remove(guildId);
        if (previous != null)
            previous.cancel(false);
        ScheduledFuture<?> future = scheduler.schedule(() -> {
            pending.remove(guildId);
            Guild fresh = main.getJda().getGuildById(guildId);
            if (fresh != null)
                silentDetect(fresh);
        }, DEBOUNCE_SECONDS, TimeUnit.SECONDS);
        pending.put(guildId, future);
    }

    /** Runs the channel/category detection and persists the IDs, without replying. */
    public void silentDetect(Guild guild) {
        try {
            BotConfigLoader loader = main.getConfigHandler().getConfig(BotConfigLoader.class);
            String report = DetectCommand.runDetect(guild, loader);
            LOGGER.info("Auto-detect synced channels for guild {} ({})", guild.getName(), guild.getId());
            LOGGER.debug("Auto-detect report:\n{}", report);
        } catch (Exception e) {
            LOGGER.error("Auto-detect failed for guild {}", guild.getId(), e);
        }
    }
}
