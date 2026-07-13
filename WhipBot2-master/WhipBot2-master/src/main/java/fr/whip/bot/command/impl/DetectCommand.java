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

import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;

public record DetectCommand(WhipBot main) implements IParentCommand {

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
            BotConfigLoader loader = main.getConfigHandler().getConfig(BotConfigLoader.class);
            String report = runDetect(guild, loader);
            event.getHook().editOriginal(report).queue();
        } catch (Exception e) {
            event.getHook().editOriginal("❌ Detection failed: " + e.getMessage()).queue();
        }
    }

    /**
     * Scans the guild's categories and channels, saves the discovered IDs to
     * config.yml, and returns a human-readable report.  Called both by the slash
     * command and by {@code AutoDetectListener} on structural changes.
     */
    public static String runDetect(Guild guild, BotConfigLoader loader) throws Exception {
        List<Category> categories = guild.getCategories();
        List<TextChannel> channels = guild.getTextChannels();

        Category tickets = findCategory(categories, name -> name.equals("tickets"));
        Category buyTickets = findCategory(categories, name -> name.contains("buy") && name.contains("ticket"));
        Category questionsTickets = findCategory(categories, name -> name.contains("question") && name.contains("ticket"));
        Category hwidTickets = findCategory(categories, name -> name.contains("hwid") && name.contains("ticket"));
        Category otherTickets = findCategory(categories, name -> name.contains("other") && name.contains("ticket"));

        // Suggestion / bug channels are split per category (customer / beta).
        TextChannel suggestionMain = null, suggestionCustomer = null, suggestionBeta = null;
        TextChannel bugMain = null, bugCustomer = null, bugBeta = null;
        for (TextChannel ch : channels) {
            String chName = ch.getName().toLowerCase(Locale.ROOT);
            String catName = ch.getParentCategory() != null
                    ? ch.getParentCategory().getName().toLowerCase(Locale.ROOT)
                    : "";
            boolean isCustomerCat = catName.contains("customer") || catName.contains("client");
            boolean isBetaCat = catName.contains("beta");

            if (chName.contains("suggestion")) {
                if (isBetaCat && suggestionBeta == null) suggestionBeta = ch;
                else if (isCustomerCat && suggestionCustomer == null) suggestionCustomer = ch;
                else if (suggestionMain == null) suggestionMain = ch;
            } else if (chName.contains("bug")) {
                if (isBetaCat && bugBeta == null) bugBeta = ch;
                else if (isCustomerCat && bugCustomer == null) bugCustomer = ch;
                else if (bugMain == null) bugMain = ch;
            }
        }

        TextChannel downloads = findChannel(channels, name -> name.contains("download"));
        TextChannel transcripts = findChannel(channels, name -> name.contains("transcript"));

        setNode(loader, "channels", "guild-id", guild.getId());
        if (tickets != null) setNode(loader, "channels", "ticket-category-id", tickets.getId());
        if (buyTickets != null) setNode(loader, "channels", "buy-ticket-category-id", buyTickets.getId());
        if (questionsTickets != null) setNode(loader, "channels", "questions-ticket-category-id", questionsTickets.getId());
        if (hwidTickets != null) setNode(loader, "channels", "hwid-ticket-category-id", hwidTickets.getId());
        if (otherTickets != null) setNode(loader, "channels", "other-ticket-category-id", otherTickets.getId());
        if (suggestionMain != null) setNode(loader, "channels", "suggestion-channel-id", suggestionMain.getId());
        if (suggestionCustomer != null) setNode(loader, "channels", "suggestion-customer-channel-id", suggestionCustomer.getId());
        if (suggestionBeta != null) setNode(loader, "channels", "suggestion-beta-channel-id", suggestionBeta.getId());
        if (bugMain != null) setNode(loader, "channels", "bug-report-channel-id", bugMain.getId());
        if (bugCustomer != null) setNode(loader, "channels", "bug-report-customer-channel-id", bugCustomer.getId());
        if (bugBeta != null) setNode(loader, "channels", "bug-report-beta-channel-id", bugBeta.getId());
        if (downloads != null) setNode(loader, "channels", "download-channel-id", downloads.getId());
        if (transcripts != null) setNode(loader, "channels", "transcript-logs-channel-id", transcripts.getId());

        loader.save();
        loader.reload();

        StringBuilder sb = new StringBuilder();
        sb.append("✅ **Detection completed!** IDs saved to `config.yml`.\n\n");
        sb.append("**Categories:**\n");
        sb.append(line("🎫 Tickets", tickets));
        sb.append(line("💳 Buy Tickets", buyTickets));
        sb.append(line("❓ Questions Tickets", questionsTickets));
        sb.append(line("🔑 HWID Tickets", hwidTickets));
        sb.append(line("📂 Other Tickets", otherTickets));
        sb.append("\n**Channels:**\n");
        sb.append(line("💡 suggestions (main)", suggestionMain));
        sb.append(line("💡 suggestions (customer)", suggestionCustomer));
        sb.append(line("💡 suggestions (beta)", suggestionBeta));
        sb.append(line("🐛 bug-reports (main)", bugMain));
        sb.append(line("🐛 bug-reports (customer)", bugCustomer));
        sb.append(line("🐛 bug-reports (beta)", bugBeta));
        sb.append(line("📥 downloads", downloads));
        sb.append(line("📋 ticket-transcripts", transcripts));
        return sb.toString();
    }

    private static Category findCategory(List<Category> categories, Predicate<String> matcher) {
        return categories.stream()
                .filter(c -> matcher.test(c.getName().toLowerCase(Locale.ROOT)))
                .findFirst().orElse(null);
    }

    private static TextChannel findChannel(List<TextChannel> channels, Predicate<String> matcher) {
        return channels.stream()
                .filter(c -> matcher.test(c.getName().toLowerCase(Locale.ROOT)))
                .findFirst().orElse(null);
    }

    private static String line(String label, net.dv8tion.jda.api.entities.channel.middleman.GuildChannel ch) {
        if (ch == null) return "• " + label + " → ❌ not found\n";
        return "• " + label + " → `" + ch.getId() + "`\n";
    }

    private static void setNode(BotConfigLoader loader, String... pathAndValue) throws SerializationException {
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
        return "detect";
    }

    @Override
    public String getDescription() {
        return "Detect existing categories & channels and save their IDs to config.yml (Admin only)";
    }
}
