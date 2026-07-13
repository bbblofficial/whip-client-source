package fr.whip.bot.manager.impl;

import fr.whip.bot.WhipBot;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.entities.Message;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;

import java.awt.Color;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class DashboardManager {

    private final WhipBot main;
    private final String dashboardChannelId = "1481527687334858752";
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final Instant startTime = Instant.now();
    private String lastDashboardMessageId = null;
    private final AtomicLong translationRequests = new AtomicLong(0);

    public DashboardManager(WhipBot main) {
        this.main = main;
    }

    public void start(JDA jda) {
        scheduler.scheduleAtFixedRate(() -> updateDashboard(jda), 0, 1, TimeUnit.MINUTES);
    }

    public void stop() {
        scheduler.shutdown();
    }

    public void incrementTranslations() {
        translationRequests.incrementAndGet();
    }

    private void updateDashboard(JDA jda) {
        try {
            TextChannel channel = jda.getTextChannelById(dashboardChannelId);
            if (channel == null)
                return;

            EmbedBuilder embed = createDashboardEmbed();

            if (lastDashboardMessageId == null) {
                channel.getHistory().retrievePast(50).queue(messages -> {
                    for (Message m : messages) {
                        if (m.getAuthor().equals(jda.getSelfUser()) && !m.getEmbeds().isEmpty() &&
                                "📊 Staff Dashboard (Live)".equals(m.getEmbeds().get(0).getTitle())) {
                            lastDashboardMessageId = m.getId();
                            m.editMessageEmbeds(embed.build()).queue();
                            return;
                        }
                    }
                    channel.sendMessageEmbeds(embed.build()).queue(msg -> lastDashboardMessageId = msg.getId());
                });
            } else {
                channel.editMessageEmbedsById(lastDashboardMessageId, embed.build()).queue(
                        null,
                        throwable -> {
                            channel.sendMessageEmbeds(embed.build()).queue(msg -> lastDashboardMessageId = msg.getId());
                        });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private EmbedBuilder createDashboardEmbed() {
        long openTickets = main.getTicketManager().getOpenTicketCount();
        Duration uptime = Duration.between(startTime, Instant.now());
        String formattedUptime = formatDuration(uptime);

        return new EmbedBuilder()
                .setTitle("📊 Staff Dashboard (Live)")
                .setColor(Color.decode("#5865F2"))
                .setThumbnail(main.getJda().getSelfUser().getAvatarUrl())
                .addField("🎫 Active Tickets", "`" + openTickets + "` open tickets", true)
                .addField("⏱️ Bot Uptime", "`" + formattedUptime + "`", true)
                .addField("📈 Quick Stats",
                        "• System Status: **Operational**\n" +
                                "• Database: **Connected**\n" +
                                "• Latency: **" + main.getJda().getGatewayPing() + "ms**\n" +
                                "• Translations: **" + translationRequests.get() + "** processed",
                        false)
                .setFooter("Whip Industries • Staff Dashboard");
    }

    private String formatDuration(Duration duration) {
        long days = duration.toDays();
        long hours = duration.toHoursPart();
        long minutes = duration.toMinutesPart();
        return String.format("%dd %dh %dm", days, hours, minutes);
    }
}
