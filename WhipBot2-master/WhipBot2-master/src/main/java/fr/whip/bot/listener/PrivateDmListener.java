package fr.whip.bot.listener;

import fr.whip.bot.WhipBot;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.buttons.Button;
import net.dv8tion.jda.api.entities.channel.concrete.Category;
import net.dv8tion.jda.api.entities.Guild;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.util.MembershipChecker;
import net.dv8tion.jda.api.entities.channel.ChannelType;
import net.dv8tion.jda.api.entities.emoji.Emoji;
import net.dv8tion.jda.api.events.message.MessageReceivedEvent;
import java.awt.Color;

public class PrivateDmListener implements Listener {

    private final WhipBot main;

    public PrivateDmListener(WhipBot main) {
        this.main = main;
    }

    @EventHandler
    public void onPrivateMessage(MessageReceivedEvent event) {
        if (event.getChannelType() != ChannelType.PRIVATE)
            return;

        System.out.println("[DM Debug] Received DM from " + event.getAuthor().getName() + ": "
                + event.getMessage().getContentRaw());

        if (event.getAuthor().isBot())
            return;

        MembershipChecker.check(event.getJDA(), event.getAuthor(),
                () -> handleDm(event),
                () -> event.getChannel().sendMessage(
                        "❌ Join the **Whip Community** server to open a ticket.").queue());
    }

    private void handleDm(MessageReceivedEvent event) {
        if (main.getTicketManager().isBanned(event.getAuthor().getId())) {
            event.getChannel().sendMessage("❌ You are banned from the ticket system.").queue();
            return;
        }

        if (main.getTicketManager().findByUserDiscordId(event.getAuthor().getId()).isPresent()) {
            return;
        }

        String raw = event.getMessage().getContentRaw();
        if (raw.toLowerCase().startsWith("/create") || raw.toLowerCase().startsWith("!create")) {
            handleManualCreate(event, raw);
            return;
        }

        if (raw.startsWith("!")) {
            return;
        }

        EmbedBuilder embed = new EmbedBuilder()
                .setTitle("📩 Whip Client Ticket")
                .setColor(Color.decode("#3498db"))
                .setThumbnail(event.getJDA().getSelfUser().getEffectiveAvatarUrl())
                .setDescription(
                        "To create a ticket and contact our team, follow these steps:\n\n" +
                                "**📩 How to create a ticket?**\n" +
                                "• Contact Whip Bot (the bot at the top of the server)\n" +
                                "• Or send a message to this bot\n" +
                                "• Or click the \"Contact Support\" button below\n" +
                                "• Then select your reason using the menu\n\n" +
                                "**⚙️ How it works**\n" +
                                "• A ticket will be created in your private messages with the bot\n" +
                                "• You can discuss with our team there\n" +
                                "• Your messages will be confirmed by a 💬 reaction. If no reaction appears, your message was not sent\n\n"
                                +
                                "**⚠️ Important**\n" +
                                "• Only one active ticket at a time\n" +
                                "• Stay respectful and patient\n" +
                                "• Provide clear and precise information")
                .setFooter("Whip Client Ticket");

        event.getChannel().sendMessageEmbeds(embed.build())
                .setComponents(ActionRow.of(
                        Button.success("ticket:create", "Contact Support")
                                .withEmoji(Emoji.fromUnicode("\uD83D\uDCE9"))))
                .queue();
    }

    private void handleManualCreate(MessageReceivedEvent event, String raw) {
        String reason = "Other";
        String[] split = raw.split(" ", 2);
        if (split.length > 1) {
            reason = split[1];
        }

        ConfigData config = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);
        String guildId = config.channels().guildId();
        if (guildId == null || guildId.isEmpty()) {
            event.getChannel().sendMessage("❌ Bot error: Guild ID not configured.").queue();
            return;
        }

        Guild guild = event.getJDA().getGuildById(guildId);
        if (guild == null) {
            event.getChannel().sendMessage("❌ Bot error: Main server not found.").queue();
            return;
        }

        Category category = guild.getCategoryById(config.channels().ticketCategoryId());
        if (category == null) {
            event.getChannel().sendMessage("❌ Bot error: Ticket category not found.").queue();
            return;
        }

        main.getTicketManager().createTicket(event.getAuthor(), reason, null, false);
    }
}
