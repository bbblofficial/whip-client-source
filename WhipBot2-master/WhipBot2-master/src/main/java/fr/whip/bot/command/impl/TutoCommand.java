package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;

import java.awt.Color;

public record TutoCommand(WhipBot main) implements IParentCommand {

    private static final long OWNER_ID = 1053050388355493989L;

    public static EmbedBuilder buildEmbed() {
        return new EmbedBuilder()
                .setThumbnail("https://cdn.discordapp.com/attachments/1158906047436689458/1158906067598708837/whip_client_logo.png")
                .setColor(Color.decode("#00b0f0"))
                .setDescription(
                        "Thank you for purchasing the client!\n" +
                        "Here is a guide to get it up and running.\n\n" +
                        "You have received a key: `example-key`. Use the command:\n\n" +
                        "`/register \"KEY\" \"Your new Whip account username\" \"Password\"`\n\n" +
                        "The bot will then invite you privately to the Customer server. " +
                        "Once there, simply verify yourself and use the `/download` command in the download channel.");
    }

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        if (event.getUser().getIdLong() != OWNER_ID) {
            event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }

        event.getChannel().sendMessageEmbeds(buildEmbed().build()).queue();
        event.reply("✅").setEphemeral(true).queue();
    }

    @Override
    public String getName() {
        return "tuto";
    }

    @Override
    public String getDescription() {
        return "Shows a tutorial on how to register and download";
    }
}
