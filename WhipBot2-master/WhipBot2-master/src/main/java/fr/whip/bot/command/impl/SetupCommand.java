package fr.whip.bot.command.impl;

import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.entities.Guild;
import net.dv8tion.jda.api.entities.channel.concrete.Category;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.DefaultMemberPermissions;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;
import org.spongepowered.configurate.serialize.SerializationException;

public record SetupCommand(WhipBot main) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        if (!event.getMember().hasPermission(Permission.ADMINISTRATOR)) {
            event.reply("❌ You do not have permission to use this command.").setEphemeral(true).queue();
            return;
        }

        Guild guild = event.getGuild();
        if (guild == null) {
            event.reply("❌ This command must be used in a guild.").setEphemeral(true).queue();
            return;
        }

        event.deferReply(true).queue();

        try {
            // ── Catégories ────────────────────────────────────────────────────
            Category tickets = guild.createCategory("🎫 Tickets").complete();
            Category buyTickets = guild.createCategory("💳 Buy Tickets").complete();
            Category questionsTickets = guild.createCategory("❓ Questions Tickets").complete();
            Category hwidTickets = guild.createCategory("🔑 HWID Tickets").complete();
            Category otherTickets = guild.createCategory("📂 Other Tickets").complete();

            // ── Salons texte ──────────────────────────────────────────────────
            TextChannel suggestions = guild.createTextChannel("💡・suggestions").complete();
            TextChannel bugReports = guild.createTextChannel("🐛・bug-reports").complete();
            TextChannel downloads = guild.createTextChannel("📥・downloads").complete();
            TextChannel transcripts = guild.createTextChannel("📋・ticket-transcripts").complete();

            // ── Sauvegarde dans config.yml ────────────────────────────────────
            BotConfigLoader loader = main.getConfigHandler().getConfig(BotConfigLoader.class);

            setNode(loader, "channels", "guild-id",                     guild.getId());
            setNode(loader, "channels", "ticket-category-id",            tickets.getId());
            setNode(loader, "channels", "buy-ticket-category-id",        buyTickets.getId());
            setNode(loader, "channels", "questions-ticket-category-id",  questionsTickets.getId());
            setNode(loader, "channels", "hwid-ticket-category-id",       hwidTickets.getId());
            setNode(loader, "channels", "other-ticket-category-id",      otherTickets.getId());
            setNode(loader, "channels", "suggestion-channel-id",         suggestions.getId());
            setNode(loader, "channels", "bug-report-channel-id",         bugReports.getId());
            setNode(loader, "channels", "download-channel-id",           downloads.getId());
            setNode(loader, "channels", "transcript-logs-channel-id",    transcripts.getId());

            loader.save();
            loader.reload();  // rechargement en mémoire

            event.getHook().editOriginal(
                    "✅ **Setup completed!** All categories and channels have been created and saved to `config.yml`.\n\n" +
                    "**Categories created:**\n" +
                    "• 🎫 Tickets → `" + tickets.getId() + "`\n" +
                    "• 💳 Buy Tickets → `" + buyTickets.getId() + "`\n" +
                    "• ❓ Questions Tickets → `" + questionsTickets.getId() + "`\n" +
                    "• 🔑 HWID Tickets → `" + hwidTickets.getId() + "`\n" +
                    "• 📂 Other Tickets → `" + otherTickets.getId() + "`\n\n" +
                    "**Channels created:**\n" +
                    "• 💡 suggestions → `" + suggestions.getId() + "`\n" +
                    "• 🐛 bug-reports → `" + bugReports.getId() + "`\n" +
                    "• 📥 downloads → `" + downloads.getId() + "`\n" +
                    "• 📋 ticket-transcripts → `" + transcripts.getId() + "`"
            ).queue();

        } catch (Exception e) {
            event.getHook().editOriginal("❌ Setup failed: " + e.getMessage()).queue();
        }
    }

    /** Helper: écrit un nœud dans le rootNode du loader et gère SerializationException. */
    private void setNode(BotConfigLoader loader, String... pathAndValue) throws SerializationException {
        // pathAndValue = { section, key, value }
        String value = pathAndValue[pathAndValue.length - 1];
        String[] path = new String[pathAndValue.length - 1];
        System.arraycopy(pathAndValue, 0, path, 0, path.length);
        loader.getRootNode().node((Object[]) path).set(value);
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data.setDefaultPermissions(DefaultMemberPermissions.enabledFor(Permission.ADMINISTRATOR));
    }

    @Override
    public String getName() {
        return "setup";
    }

    @Override
    public String getDescription() {
        return "Auto-create all required channels & categories and save their IDs to config.yml (Admin only)";
    }
}
