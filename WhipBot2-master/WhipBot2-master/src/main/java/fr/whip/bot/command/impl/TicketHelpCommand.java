package fr.whip.bot.command.impl;

import fr.whip.bot.command.IParentCommand;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

import java.awt.Color;

public record TicketHelpCommand() implements IParentCommand {

    private static final String IMG1 = "https://media.discordapp.net/attachments/1399589185593278545/1482550922293940395/discord.png?ex=69b75ca4&is=69b60b24&hm=8b968a97b3eb262732478dbcd4bc7818b65525c3f3c5f487b881b38c4b7b2e8b&format=webp&quality=lossless&width=1848&height=695&";
    private static final String IMG2 = "https://media.discordapp.net/attachments/1399589185593278545/1482552352501141756/discordv2.png?ex=69b75df9&is=69b60c79&hm=07c816dc245f197119135555d0399159038e3c20fe1da652ad87c694bab64c1a&format=webp&quality=lossless&width=708&height=361&";

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        EmbedBuilder embed1 = new EmbedBuilder()
                .setColor(Color.decode("#3498db"))
                .setDescription("To enable private messages from server members, follow the steps shown below:")
                .setImage(IMG1);

        EmbedBuilder embed2 = new EmbedBuilder()
                .setColor(Color.decode("#3498db"))
                .setImage(IMG2);

        event.replyEmbeds(embed1.build(), embed2.build()).setEphemeral(true).queue();
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data;
    }

    @Override
    public String getName() {
        return "tickethelp";
    }

    @Override
    public String getDescription() {
        return "Shows how to enable private messages to use the ticket system";
    }
}
