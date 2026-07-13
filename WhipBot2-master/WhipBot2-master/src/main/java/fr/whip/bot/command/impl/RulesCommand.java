package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.buttons.Button;

import java.awt.Color;

public record RulesCommand(WhipBot main) implements IParentCommand {

    private static final long STAFF_ROLE_ID = 1159089894983991378L;
    private static final long OWNER_ID = 1053050388355493989L;
    public static final long RULES_ROLE_ID = 1162479298754654370L;
    public static final long CUSTOMER_ROLE_ID = 1370704588671418520L;

    public static final String ACCEPT_BUTTON_ID = "rules:accept";
    public static final String CUSTOMER_BUTTON_ID = "rules:customer";

    public static EmbedBuilder buildEmbed() {
        return new EmbedBuilder()
                .setThumbnail(
                        "https://cdn.discordapp.com/attachments/1158906047436689458/1158906067598708837/whip_client_logo.png")
                .setColor(Color.decode("#00b0f0"))
                .setDescription(
                        "> Treat everyone with respect. Insults, racism, or any inappropriate language are strictly prohibited.\n\n"
                                +
                                "> The disclosure of private information, including names, IP addresses, or any personal data, is strictly forbidden.\n\n"
                                +
                                "> Do not ping staff members. If you need assistance, please open a ticket.\n\n" +
                                "> Spam is not allowed, and NSFW or gore content is strictly prohibited.\n\n" +
                                "> Any form of dispute, drama, or conflict within the server is not permitted.\n\n" +
                                "> Screensharers are not eligible for purchase. If you are unsure about your status, please ask before making a purchase.\n\n"
                                +
                                "> Leaking any private information related to the client (including exe, dll, tickets, or detections) will result in an immediate ban.\n\n"
                                +
                                "> We reserve the right to remove your license and ban you if you violate any of the server rules.\n\n"
                                +
                                "> Please make sure you have read and understood the Discord Guidelines:\n" +
                                "> https://discord.com/guidelines");
    }

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        if (event.getMember() == null || !event.isFromGuild())
            return;

        if (event.getUser().getIdLong() != OWNER_ID) {
            event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }

        event.getChannel().sendMessageEmbeds(buildEmbed().build())
                .setComponents(ActionRow.of(Button.success(ACCEPT_BUTTON_ID, "✅ Accept rules")))
                .queue();
        event.reply("✅").setEphemeral(true).queue();
    }

    @Override
    public String getName() {
        return "rules";
    }

    @Override
    public String getDescription() {
        return "Displays the server rules";
    }
}
