package fr.whip.bot.command.impl;

import fr.whip.api.model.License;
import fr.whip.api.model.LicenseStatus;
import fr.whip.api.model.ProductType;
import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.PermissionsData;
import fr.whip.bot.manager.impl.LicenseManager;
import fr.whip.bot.manager.impl.ProductManager;
import fr.whip.bot.manager.impl.UserManager;
import fr.whip.bot.util.PermissionChecker;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.components.actionrow.ActionRow;
import net.dv8tion.jda.api.components.buttons.Button;
import net.dv8tion.jda.api.entities.emoji.Emoji;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.OptionMapping;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.OptionData;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;
import net.dv8tion.jda.api.interactions.commands.build.SubcommandData;

import java.awt.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

public record LicenseCommand(WhipBot main) implements IParentCommand {

    private static final String COPY_KEY_PREFIX = "license:copykey:";

    public LicenseCommand {
        main.getComponentHandler().register(COPY_KEY_PREFIX, interaction -> {
            String key = interaction.getComponentId().substring(COPY_KEY_PREFIX.length());
            // Ephemeral replies don't exist in DMs, so only request it inside a guild.
            interaction.reply("```\n" + key + "\n```").setEphemeral(interaction.isFromGuild()).queue();
        });
    }

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        String subcommand = event.getSubcommandName();
        if (subcommand == null)
            return;

        LicenseManager licenseManager = main.getLicenseManager();
        ProductManager productManager = main.getProductManager();
        UserManager userManager = main.getUserManager();

        event.deferReply(true).queue();

        switch (subcommand) {
            case "create" -> handleCreate(event, licenseManager, productManager);
            case "revoke" -> handleRevoke(event, licenseManager);
            case "list" -> handleList(event, licenseManager, userManager);
        }
    }

    private void handleCreate(SlashCommandInteractionEvent event, LicenseManager licenseManager,
            ProductManager productManager) {
        PermissionsData perms = main.getConfigHandler()
                .<ConfigData>getPrototypeConfig(BotConfigLoader.class).permissions();
        if (!PermissionChecker.isUser(event.getUser(), perms.singerieUserId())) {
            event.getHook().sendMessage("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }

        String productTypeStr = event.getOption("product").getAsString();
        boolean lifetime = event.getOption("lifetime", false, OptionMapping::getAsBoolean);
        int days = event.getOption("days", 30, OptionMapping::getAsInt);

        ProductType productType;
        try {
            productType = ProductType.valueOf(productTypeStr);
        } catch (IllegalArgumentException e) {
            event.getHook().sendMessage("Invalid product type.").setEphemeral(true).queue();
            return;
        }

        productManager.findByCode(productType).ifPresentOrElse(product -> {
            License license = new License();
            license.setLicenseKey(licenseManager.generateLicenseKey());
            license.setProduct(product);
            license.setStatus(LicenseStatus.active);

            if (!lifetime) {
                license.setExpiresAt(Instant.now().plus(days, ChronoUnit.DAYS));
            }

            licenseManager.save(license);

            String duration = lifetime ? "Lifetime" : days + " days";
            String expires = lifetime ? "Never" : "<t:" + license.getExpiresAt().getEpochSecond() + ":R>";

            EmbedBuilder embed = new EmbedBuilder()
                    .setTitle("License Created")
                    .setColor(Color.GREEN)
                    .addField("License Key", "||" + license.getLicenseKey() + "||", false)
                    .addField("Product", product.getName(), true)
                    .addField("Duration", duration, true)
                    .addField("Expires", expires, true);

            net.dv8tion.jda.api.entities.MessageEmbed built = embed.build();
            Button copyButton = Button.secondary(COPY_KEY_PREFIX + license.getLicenseKey(), "Copy Key")
                    .withEmoji(Emoji.fromUnicode("📋"));
            event.getMessageChannel().sendMessageEmbeds(built)
                    .setComponents(ActionRow.of(copyButton))
                    .queue();

            if (event.getChannel() instanceof net.dv8tion.jda.api.entities.channel.concrete.TextChannel textChannel) {
                main.getTicketManager().findByStaffChannelId(textChannel.getId())
                        .ifPresent(ticket -> main.getTicketManager().relayEmbedToUser(ticket, built,
                                ActionRow.of(copyButton)));
            }

            event.getHook().sendMessage("License created and posted to the channel.").setEphemeral(true).queue();
        }, () -> event.getHook().sendMessage("Product not found.").setEphemeral(true).queue());
    }

    private void handleRevoke(SlashCommandInteractionEvent event, LicenseManager licenseManager) {
        PermissionsData perms = main.getConfigHandler()
                .<ConfigData>getPrototypeConfig(BotConfigLoader.class).permissions();
        if (!PermissionChecker.isUser(event.getUser(), perms.singerieUserId())) {
            event.getHook().sendMessage("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }

        String licenseKey = event.getOption("key").getAsString();

        licenseManager.findByLicenseKey(licenseKey).ifPresentOrElse(license -> {
            license.setStatus(LicenseStatus.revoked);
            licenseManager.save(license);
            event.getHook().sendMessage("License `" + licenseKey + "` has been revoked.").setEphemeral(true).queue();
        }, () -> event.getHook().sendMessage("License not found.").setEphemeral(true).queue());
    }

    private void handleList(SlashCommandInteractionEvent event, LicenseManager licenseManager,
            UserManager userManager) {
        PermissionsData perms = main.getConfigHandler()
                .<ConfigData>getPrototypeConfig(BotConfigLoader.class).permissions();
        if (!PermissionChecker.hasRole(event.getMember(), perms.customerRoleId())) {
            event.getHook().sendMessage("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }

        String discordId = event.getUser().getId();

        userManager.findByDiscordId(discordId).ifPresentOrElse(user -> {
            List<License> licenses = licenseManager.findByUser(user);

            if (licenses.isEmpty()) {
                event.getHook().sendMessage("You don't have any licenses.").setEphemeral(true).queue();
                return;
            }

            EmbedBuilder embed = new EmbedBuilder()
                    .setTitle("Your Licenses")
                    .setColor(Color.BLUE);

            for (License license : licenses) {
                String status = license.isValid() ? "Active" : license.getStatus().name();
                String expiry = license.getExpiresAt() != null
                        ? "<t:" + license.getExpiresAt().getEpochSecond() + ":R>"
                        : "Never";

                embed.addField(
                        license.getProduct().getName(),
                        "Status: " + status + "\nExpires: " + expiry,
                        true);
            }

            event.getHook().sendMessageEmbeds(embed.build()).setEphemeral(true).queue();
        }, () -> event.getHook().sendMessage("You are not registered. Use `/register` first.").setEphemeral(true)
                .queue());
    }

    @Override
    public String getName() {
        return "license";
    }

    @Override
    public String getDescription() {
        return "Manage user licenses";
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data.addSubcommands(
                new SubcommandData("create", "Create a new license")
                        .addOptions(buildProductTypeOption("product", "The product", true))
                        .addOption(OptionType.BOOLEAN, "lifetime", "Create a lifetime license", false)
                        .addOption(OptionType.INTEGER, "days", "License duration in days", false),
                new SubcommandData("revoke", "Revoke a license")
                        .addOption(OptionType.STRING, "key", "The license key to revoke", true),
                new SubcommandData("list", "List your licenses"));
    }

    private static OptionData buildProductTypeOption(String name, String description, boolean required) {
        OptionData option = new OptionData(OptionType.STRING, name, description, required);
        for (ProductType type : ProductType.values()) {
            option.addChoice(type.getDisplayName(), type.name());
        }
        return option;
    }
}
