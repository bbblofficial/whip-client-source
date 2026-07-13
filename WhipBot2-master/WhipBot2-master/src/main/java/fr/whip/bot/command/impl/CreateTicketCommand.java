package fr.whip.bot.command.impl;

import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.manager.impl.TicketManager;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.OptionData;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;

public record CreateTicketCommand(TicketManager ticketManager, ConfigData configData, net.dv8tion.jda.api.JDA jda)
        implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        String discordId = event.getUser().getId();

        if (ticketManager.findByUserDiscordId(discordId).isPresent()) {
            event.reply("You already have an open ticket!").setEphemeral(true).queue();
            return;
        }

        String reason = event.getOption("reason") != null ? event.getOption("reason").getAsString() : "Other";

        event.deferReply(true).queue();
        ticketManager.createTicket(event.getUser(), reason, event.getHook(), true);
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data.addOptions(new OptionData(OptionType.STRING, "reason", "Reason for creating the ticket", true)
                .addChoice("Reset HWID", "Reset HWID")
                .addChoice("Question", "Question")
                .addChoice("Others", "Others")
                .addChoice("Buy", "Buy"));
    }

    @Override
    public String getName() {
        return "create";
    }

    @Override
    public String getDescription() {
        return "Create a support ticket";
    }
}
