package fr.whip.bot.command.impl;

import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.data.entity.TicketEntity;
import fr.whip.bot.manager.impl.TicketManager;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;

import java.util.Optional;

public record CloseTicketCommand(TicketManager ticketManager) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        if (event.getChannel() instanceof TextChannel textChannel) {
            Optional<TicketEntity> ticketOpt = ticketManager.findByStaffChannelId(textChannel.getId());
            if (ticketOpt.isPresent()) {
                TicketEntity ticket = ticketOpt.get();
                event.deferReply(true).flatMap(net.dv8tion.jda.api.interactions.InteractionHook::deleteOriginal)
                        .queue();
                ticketManager.closeTicket(event.getJDA(), ticket, true);
            } else {
                event.reply("This is not a valid ticket channel.").setEphemeral(true).queue();
            }
        } else {
            Optional<TicketEntity> ticketOpt = ticketManager.findByUserDiscordId(event.getUser().getId());
            if (ticketOpt.isPresent()) {
                event.deferReply(true).flatMap(net.dv8tion.jda.api.interactions.InteractionHook::deleteOriginal)
                        .queue();
                ticketManager.closeTicket(event.getJDA(), ticketOpt.get(), false);
            } else {
                event.reply("You do not have an open ticket.").setEphemeral(true).queue();
            }
        }
    }

    @Override
    public String getName() {
        return "close";
    }

    @Override
    public String getDescription() {
        return "Closes the current ticket";
    }
}
