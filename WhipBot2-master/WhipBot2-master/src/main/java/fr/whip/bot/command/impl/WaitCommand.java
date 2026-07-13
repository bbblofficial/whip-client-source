package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.PermissionsData;
import fr.whip.bot.data.entity.TicketEntity;
import fr.whip.bot.util.PermissionChecker;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

import java.awt.Color;
import java.util.Optional;

public record WaitCommand(WhipBot main) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        PermissionsData perms = main.getConfigHandler()
                .<ConfigData>getPrototypeConfig(BotConfigLoader.class).permissions();
        if (!PermissionChecker.hasRole(event.getMember(), perms.supportRoleId())) {
            event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }

        if (!(event.getChannel() instanceof TextChannel textChannel)) {
            event.reply("This command can only be used in a text channel.").setEphemeral(true).queue();
            return;
        }

        Optional<TicketEntity> ticketOpt = main.getTicketManager().findByStaffChannelId(textChannel.getId());
        if (ticketOpt.isEmpty()) {
            event.reply("This channel is not a valid ticket channel.").setEphemeral(true).queue();
            return;
        }

        TicketEntity ticket = ticketOpt.get();

        EmbedBuilder embed = new EmbedBuilder()
                .setTitle("⏳ Please Wait")
                .setColor(Color.ORANGE)
                .setDescription("An owner or senior staff member has been notified and will be with you shortly. " +
                        "Please be patient while we look into your request.");

        event.getJDA().retrieveUserById(ticket.getUserDiscordId()).queue(user -> {
            user.openPrivateChannel().queue(privateChannel ->
                    privateChannel.sendMessageEmbeds(embed.build()).queue());
        });

        EmbedBuilder staffEmbed = new EmbedBuilder()
                .setTitle("⏳ Customer is Waiting")
                .setColor(Color.ORANGE)
                .setDescription("<@" + ticket.getUserDiscordId() + "> has been set to **wait** status.\n" +
                        "An owner or senior staff member should follow up.")
                .setFooter("Wait set by " + event.getUser().getName());

        textChannel.sendMessageEmbeds(staffEmbed.build()).queue();

        event.reply("✅ Wait message sent to the user.").setEphemeral(true).queue();
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data;
    }

    @Override
    public String getName() {
        return "wait";
    }

    @Override
    public String getDescription() {
        return "Tells the user to wait for an owner (Staff Only)";
    }
}
