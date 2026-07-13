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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class TicketBanCommand implements IParentCommand {

    private final WhipBot main;

    public TicketBanCommand(WhipBot main) {
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
        String reason = event.getOption("reason") != null ? event.getOption("reason").getAsString()
                : "No reason specified";

        // Ack the interaction first — the ban runs two synchronous DB queries,
        // which can exceed Discord's 3s reply window and make the command fail
        // ("This interaction failed"). Do the DB work off the gateway thread and
        // respond via the hook (token valid for 15 min).
        event.deferReply().queue();
        CompletableFuture.runAsync(() -> {
            if (main.getTicketManager().isBanned(target.getId())) {
                event.getHook().editOriginalEmbeds(embed("#e74c3c", "❌ This user is already banned from tickets."))
                        .queue(m -> event.getHook().deleteOriginal().queueAfter(1, TimeUnit.MINUTES, null, t -> {}));
                return;
            }

            main.getTicketManager().banUser(target.getId(), reason, event.getUser().getName());
            MessageEmbed success = new EmbedBuilder()
                    .setColor(Color.decode("#2ecc71"))
                    .setTitle("✅ User Banned")
                    .setDescription("**" + target.getName() + "** has been banned from tickets.")
                    .addField("Reason", reason, false)
                    .build();
            event.getHook().editOriginalEmbeds(success)
                    .queue(m -> event.getHook().deleteOriginal().queueAfter(1, TimeUnit.MINUTES, null, t -> {}));
        });
    }

    /** Small single-line coloured embed used for status/permission replies. */
    private static MessageEmbed embed(String hex, String description) {
        return new EmbedBuilder().setColor(Color.decode(hex)).setDescription(description).build();
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data.addOption(OptionType.USER, "user", "The user to ban", true)
                .addOption(OptionType.STRING, "reason", "The reason for the ban", false);
    }

    @Override
    public String getName() {
        return "ticketban";
    }

    @Override
    public String getDescription() {
        return "Bans a user from the ticket system";
    }
}
