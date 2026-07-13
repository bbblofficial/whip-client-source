package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.PermissionsData;
import fr.whip.bot.util.PermissionChecker;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.entities.MessageEmbed;
import net.dv8tion.jda.api.entities.User;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

import java.awt.Color;
import java.util.concurrent.TimeUnit;

public class TicketUnbanCommand implements IParentCommand {

    private final WhipBot main;

    public TicketUnbanCommand(WhipBot main) {
        this.main = main;
    }

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        PermissionsData perms = main.getConfigHandler()
                .<ConfigData>getPrototypeConfig(BotConfigLoader.class).permissions();
        if (!PermissionChecker.hasRoleOrAdmin(event.getMember(), perms.supportRoleId())) {
            event.replyEmbeds(embed("#e74c3c", "❌ You don't have permission to use this command."))
                    .setEphemeral(true).queue();
            return;
        }

        User target = event.getOption("user").getAsUser();

        if (!main.getTicketManager().isBanned(target.getId())) {
            event.replyEmbeds(embed("#e74c3c", "❌ This user is not banned from tickets."))
                    .setEphemeral(true).queue();
            return;
        }

        main.getTicketManager().unbanUser(target.getId());
        MessageEmbed success = new EmbedBuilder()
                .setColor(Color.decode("#2ecc71"))
                .setTitle("✅ User Unbanned")
                .setDescription("**" + target.getName() + "** has been unbanned from tickets.")
                .build();
        event.replyEmbeds(success)
                .queue(hook -> hook.deleteOriginal().queueAfter(1, TimeUnit.MINUTES, null, t -> {}));
    }

    /** Small single-line coloured embed used for status/permission replies. */
    private static MessageEmbed embed(String hex, String description) {
        return new EmbedBuilder().setColor(Color.decode(hex)).setDescription(description).build();
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data.addOption(OptionType.USER, "user", "The user to unban", true);
    }

    @Override
    public String getName() {
        return "ticketunban";
    }

    @Override
    public String getDescription() {
        return "Unbans a user from the ticket system";
    }
}
