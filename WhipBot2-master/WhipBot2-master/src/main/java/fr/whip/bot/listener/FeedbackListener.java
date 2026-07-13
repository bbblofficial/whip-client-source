package fr.whip.bot.listener;

import fr.whip.bot.WhipBot;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ChannelsData;
import fr.whip.bot.data.ConfigData;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.entities.Message;
import net.dv8tion.jda.api.entities.emoji.Emoji;
import net.dv8tion.jda.api.events.message.MessageReceivedEvent;

import java.awt.Color;

public class FeedbackListener implements Listener {

    private final WhipBot main;

    public FeedbackListener(WhipBot main) {
        this.main = main;
    }

    @EventHandler
    public void onMessageReceived(MessageReceivedEvent event) {
        if (event.getAuthor().isBot())
            return;
        if (!event.isFromGuild())
            return;

        ConfigData configData = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);
        ChannelsData channels = configData.channels();
        String channelId = event.getChannel().getId();
        boolean isSuggestion = matchesAny(channelId, channels.suggestionChannelId(),
                channels.suggestionCustomerChannelId(), channels.suggestionBetaChannelId());
        boolean isBugReport = matchesAny(channelId, channels.bugReportChannelId(),
                channels.bugReportCustomerChannelId(), channels.bugReportBetaChannelId());

        if (!isSuggestion && !isBugReport)
            return;

        event.getMessage().delete().queue();

        Color color = isSuggestion ? Color.decode("#3498db") : Color.decode("#ED4245");
        String emoji = isSuggestion ? "💡" : "🐛";
        EmbedBuilder embed = new EmbedBuilder()
                .setAuthor(event.getAuthor().getName(), null, event.getAuthor().getEffectiveAvatarUrl())
                .setColor(color)
                .setDescription("### 📝 Content\n" + event.getMessage().getContentRaw())
                .addField("\u200B", "`⏳ In waiting` ", false);

        java.util.List<net.dv8tion.jda.api.EmbedBuilder> imageEmbeds = new java.util.ArrayList<>();
        imageEmbeds.add(embed);
        boolean mainImageSet = false;

        for (Message.Attachment attachment : event.getMessage().getAttachments()) {
            if (attachment.isImage()) {
                if (!mainImageSet) {
                    embed.setImage(attachment.getUrl());
                    mainImageSet = true;
                } else {
                    imageEmbeds.add(new EmbedBuilder().setColor(color).setImage(attachment.getUrl()));
                }
            } else {
                embed.addField("📎 Attachment", "[Click to Download](" + attachment.getUrl() + ")", false);
            }
        }

        event.getChannel().sendMessageEmbeds(imageEmbeds.stream().map(EmbedBuilder::build).toList())
                .queue(msg -> {
                    // Reactions are decorative only (community votes). The status is changed
                    // exclusively via the /suggestion and /report commands, never by reacting.
                    msg.addReaction(Emoji.fromUnicode("✅")).queue();
                    msg.addReaction(Emoji.fromUnicode("❌")).queue();

                    msg.createThreadChannel(emoji + " Discussion - " + event.getAuthor().getName()).queue();
                });
    }

    private boolean matchesAny(String channelId, String... ids) {
        for (String id : ids) {
            if (id != null && !id.isEmpty() && id.equals(channelId)) {
                return true;
            }
        }
        return false;
    }
}
