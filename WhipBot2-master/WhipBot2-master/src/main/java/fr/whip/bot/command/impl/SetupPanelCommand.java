package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.PermissionsData;
import fr.whip.bot.util.PermissionChecker;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.buttons.Button;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

import java.awt.Color;

public record SetupPanelCommand(WhipBot main) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        PermissionsData perms = main.getConfigHandler()
                .<ConfigData>getPrototypeConfig(BotConfigLoader.class).permissions();
        if (!PermissionChecker.isUser(event.getUser(), perms.singerieUserId())) {
            event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }

        EmbedBuilder embed = new EmbedBuilder()
                .setTitle("\uD83D\uDCE9 Whip Client Ticket")
                .setColor(Color.decode("#3498db"))
                .setThumbnail(
                        "https://cdn.discordapp.com/attachments/1158906047436689458/1158906067598708837/whip_client_logo.png")
                .setDescription(
                        "To create a ticket and contact our team, follow these steps:\n\n" +
                                "\uD83D\uDCE9 **How to create a ticket?**\n" +
                                "• Contact Whip Bot (the bot at the top of the server)\n" +
                                "• Or send a message to this bot\n" +
                                "• Or click the \"Contact Support\" button below\n" +
                                "• Then select your reason using the menu\n\n" +
                                "⚙️ **How it works**\n" +
                                "• A ticket will be created in your private messages with the bot\n" +
                                "• You can discuss with our team there\n" +
                                "• Your messages will be confirmed by a \uD83D\uDCAC reaction. If no reaction appears, your message was not sent\n\n"
                                +
                                "⚠️ **Important**\n" +
                                "• Only one active ticket at a time\n" +
                                "• Stay respectful and patient\n" +
                                "• Provide clear and precise information\n\n" +
                                "📩 If you don't receive a private message from the bot use `/tickethelp`")
                .setFooter("Whip Client Ticket");

        event.getChannel().sendMessageEmbeds(embed.build())
                .setComponents(ActionRow.of(
                        Button.success("ticket:create", "Contact Support")
                                .withEmoji(net.dv8tion.jda.api.entities.emoji.Emoji.fromUnicode("\uD83D\uDCE9"))))
                .queue();

        event.reply("✅ Panel sent!").setEphemeral(true).queue();
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data;
    }

    @Override
    public String getName() {
        return "setup-panel";
    }

    @Override
    public String getDescription() {
        return "Send the ticket panel in this channel (Admin only)";
    }
}
