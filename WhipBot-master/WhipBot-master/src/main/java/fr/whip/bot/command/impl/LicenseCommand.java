package fr.whip.bot.command.impl;

import fr.whip.api.model.License;
import fr.whip.api.model.LicenseStatus;
import fr.whip.api.model.ProductType;
import fr.whip.bot.command.base.ParentComplexBaseCommand;
import fr.whip.bot.manager.impl.LicenseManager;
import fr.whip.bot.manager.impl.ProductManager;
import fr.whip.bot.manager.impl.UserManager;
import fr.whip.bot.util.OptionUtils;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.interactions.commands.OptionType;

import java.awt.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class LicenseCommand extends ParentComplexBaseCommand {

    public LicenseCommand(LicenseManager licenseManager, ProductManager productManager, UserManager userManager) {
        registerChildCommand("create", "Create a new license for a product", event -> {
            if (!event.getMember().hasPermission(Permission.ADMINISTRATOR)) {
                event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
                return;
            }

            String productTypeStr = OptionUtils.getStringOption(event, "product").orElseThrow();
            boolean lifetime = OptionUtils.getBooleanOption(event, "lifetime").orElse(false);
            int days = OptionUtils.getIntOption(event, "days").orElse(30);

            ProductType productType;
            try {
                productType = ProductType.valueOf(productTypeStr);
            } catch (IllegalArgumentException e) {
                event.reply("Invalid product type.").setEphemeral(true).queue();
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

                event.replyEmbeds(embed.build()).setEphemeral(true).queue();
            }, () -> event.reply("Product not found. Create it first with `/product create`.").setEphemeral(true).queue());
        }, Optional.of(data -> data
                .addOptions(ProductCommand.buildProductTypeOption("product", "The product", true))
                .addOption(OptionType.BOOLEAN, "lifetime", "Create a lifetime license", false)
                .addOption(OptionType.INTEGER, "days", "License duration in days (default: 30, ignored if lifetime)", false)));

        registerChildCommand("revoke", "Revoke a license", event -> {
            if (!event.getMember().hasPermission(Permission.ADMINISTRATOR)) {
                event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
                return;
            }

            String licenseKey = OptionUtils.getStringOption(event, "key").orElseThrow();

            licenseManager.findByLicenseKey(licenseKey).ifPresentOrElse(license -> {
                license.setStatus(LicenseStatus.revoked);
                licenseManager.save(license);

                event.reply("License `" + licenseKey + "` has been revoked.").setEphemeral(true).queue();
            }, () -> event.reply("License not found.").setEphemeral(true).queue());
        }, Optional.of(data -> data
                .addOption(OptionType.STRING, "key", "The license key to revoke", true)));

        registerChildCommand("list", "List your licenses", event -> {
            String discordId = event.getUser().getId();

            userManager.findByDiscordId(discordId).ifPresentOrElse(user -> {
                var licenses = licenseManager.findByUser(user);

                if (licenses.isEmpty()) {
                    event.reply("You don't have any licenses.").setEphemeral(true).queue();
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
                            true
                    );
                }

                event.replyEmbeds(embed.build()).setEphemeral(true).queue();
            }, () -> event.reply("You are not registered. Use `/register` first.").setEphemeral(true).queue());
        });

        registerChildCommand("info", "Get info about a license", event -> {
            String licenseKey = OptionUtils.getStringOption(event, "key").orElseThrow();
            String discordId = event.getUser().getId();
            boolean isAdmin = event.getMember().hasPermission(Permission.ADMINISTRATOR);

            licenseManager.findByLicenseKey(licenseKey).ifPresentOrElse(license -> {
                if (!isAdmin && (license.getUser() == null || !discordId.equals(license.getUser().getDiscordId()))) {
                    event.reply("You don't have permission to view this license.").setEphemeral(true).queue();
                    return;
                }

                EmbedBuilder embed = new EmbedBuilder()
                        .setTitle("License Info")
                        .setColor(license.isValid() ? Color.GREEN : Color.RED)
                        .addField("Product", license.getProduct().getName(), true)
                        .addField("Status", license.getStatus().name(), true)
                        .addField("Valid", license.isValid() ? "Yes" : "No", true)
                        .addField("Created", "<t:" + license.getCreatedAt().getEpochSecond() + ":F>", false);

                if (license.getExpiresAt() != null) {
                    embed.addField("Expires", "<t:" + license.getExpiresAt().getEpochSecond() + ":R>", true);
                }

                if (license.getUser() != null) {
                    embed.addField("Owner", license.getUser().getUsername(), true);
                } else {
                    embed.addField("Owner", "Unassigned", true);
                }

                event.replyEmbeds(embed.build()).setEphemeral(true).queue();
            }, () -> event.reply("License not found.").setEphemeral(true).queue());
        }, Optional.of(data -> data
                .addOption(OptionType.STRING, "key", "The license key", true)));
    }

    @Override
    public String getName() {
        return "license";
    }

    @Override
    public String getDescription() {
        return "Manage licenses";
    }
}