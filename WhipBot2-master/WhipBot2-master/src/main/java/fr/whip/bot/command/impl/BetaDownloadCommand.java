package fr.whip.bot.command.impl;

import fr.whip.api.model.Download;
import fr.whip.api.model.License;
import fr.whip.api.model.Product;
import fr.whip.api.model.User;
import fr.whip.bot.WhipBot;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.data.log.LogCategory;
import fr.whip.bot.config.impl.BotConfigLoader;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.data.PermissionsData;
import fr.whip.bot.manager.impl.DownloadManager;
import fr.whip.bot.manager.impl.LicenseManager;
import fr.whip.bot.manager.impl.UserManager;
import fr.whip.bot.util.LoaderPatcher;
import fr.whip.bot.util.PeFingerprint;
import fr.whip.bot.util.PermissionChecker;
import net.dv8tion.jda.api.EmbedBuilder;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.Color;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

public record BetaDownloadCommand(WhipBot main) implements IParentCommand {

    private static final Logger LOGGER = LoggerFactory.getLogger(BetaDownloadCommand.class);

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        if (event.getMember() == null || !event.isFromGuild())
            return;

        ConfigData configData = main.getConfigHandler().getPrototypeConfig(BotConfigLoader.class);
        PermissionsData perms = configData.permissions();
        UserManager userManager = main.getUserManager();
        LicenseManager licenseManager = main.getLicenseManager();
        DownloadManager downloadManager = main.getDownloadManager();

        if (!PermissionChecker.hasRole(event.getMember(), perms.betaRoleId())) {
            event.reply("You don't have permission to use this command.").setEphemeral(true).queue();
            return;
        }
        if (!PermissionChecker.inChannel(event.getChannel(), configData.channels().downloadBetaChannelId())) {
            event.reply("This command can only be used in the beta download channel.").setEphemeral(true).queue();
            return;
        }

        String discordId = event.getMember().getId();

        User user = userManager.findByDiscordId(discordId).orElse(null);
        if (user == null) {
            event.reply("You need to register first! Use `/register` with a valid license key.").setEphemeral(true)
                    .queue();
            return;
        }

        List<License> licenses = licenseManager.findByUser(user);
        License activeLicense = licenses.stream().filter(License::isValid).findFirst().orElse(null);

        if (activeLicense == null) {
            event.reply("You don't have any active license.").setEphemeral(true).queue();
            return;
        }

        Product product = activeLicense.getProduct();
        if (product == null) {
            event.reply("Your license is not associated with any product. Contact an administrator.").setEphemeral(true)
                    .queue();
            return;
        }

        if (!configData.loaderPath().exists()) {
            event.reply("The loader is currently unavailable. Contact an administrator.").setEphemeral(true).queue();
            return;
        }

        fr.whip.bot.service.FileHostingService fileHostingService = main.getFileHostingService();
        if (fileHostingService == null) {
            event.reply("The download service is currently unavailable. Contact an administrator.").setEphemeral(true).queue();
            return;
        }

        event.deferReply(true).queue();

        try {
            downloadManager.revokeAllForUserAndProduct(user, product);

            String downloadId = downloadManager.generateDownloadId();
            LoaderPatcher.PatchResult patchResult = LoaderPatcher.patchLoader(configData.loaderPath(), downloadId);
            byte[] patchedLoader = patchResult.patchedBytes();

            Download download = new Download();
            download.setDownloadId(downloadId);
            download.setUser(user);
            download.setProduct(product);
            download.setDownloadedAt(Instant.now());
            download.setAuthSalt(patchResult.authSalt());
            download.setAlgoSeed(patchResult.algoSeed());
            download.setExpectedFingerprint(patchResult.codeFingerprint());
            downloadManager.save(download);

            main.getAuditManager().event("download.generate", "download", user.getId(),
                    "Loader généré — produit=" + product.getName() + " — " + user.getUsername());

            String fileName = LoaderPatcher.generateFileName();

            if (fileHostingService != null && configData.fileHosting().enabled()) {
                String downloadUrl = fileHostingService.createTemporaryLink(patchedLoader, fileName);

                long expiresAt = Instant.now().plusSeconds(60).getEpochSecond();

                EmbedBuilder embed = new EmbedBuilder()
                        .setTitle("Whip Loader — Ready")
                        .setColor(Color.decode("#3498db"))
                        .setThumbnail(event.getJDA().getSelfUser().getEffectiveAvatarUrl())
                        .setDescription("**[→ Download your loader](" + downloadUrl + ")**\n\n" +
                                "⏱️ Expires <t:" + expiresAt + ":R>\n" +
                                "⚠️ This link can only be used once")
                        .setFooter("Whip Client");

                event.getUser().openPrivateChannel().queue(
                        channel -> channel.sendMessageEmbeds(embed.build()).queue(
                                message -> {
                                    message.delete().queueAfter(1, TimeUnit.MINUTES);
                                    ephemeralNotice(event, "✅ Sent in your DMs!");
                                    LOGGER.info("Download {} link sent via DM to user {} ({}) for product {}",
                                            downloadId, user.getUsername(), discordId, product.getName());
                                },
                                error -> {
                                    ephemeralNotice(event, "❌ Failed to send you a DM. Make sure your DMs are open!");
                                    LOGGER.error("Failed to send DM embed to user {}", discordId, error);
                                }
                        ),
                        error -> ephemeralNotice(event, "❌ Your direct messages are disabled. Enable DMs from server members to receive your loader.")
                );
            } else {
                event.getUser().openPrivateChannel().queue(channel -> {
                    net.dv8tion.jda.api.utils.FileUpload fileUpload = net.dv8tion.jda.api.utils.FileUpload.fromData(patchedLoader, fileName);
                    channel.sendFiles(fileUpload).queue(
                            success -> {
                                ephemeralNotice(event, "✅ Sent in your DMs!");
                                LOGGER.info("Download {} sent to user {} ({}) for product {}",
                                        downloadId, user.getUsername(), discordId, product.getName());
                            },
                            error -> {
                                ephemeralNotice(event, "❌ Failed to send you a DM. Make sure your DMs are open!");
                                LOGGER.error("Failed to send download to user {}", discordId, error);
                            }
                    );
                }, error -> ephemeralNotice(event, "❌ Your direct messages are disabled. Enable DMs from server members to receive your loader."));
            }

            main.getLogManager().info(LogCategory.DOWNLOAD, discordId,
                    "Download | id=" + downloadId + " product=" + product.getName());

        } catch (Exception e) {
            LOGGER.error("Error processing download for user {}", discordId, e);
            ephemeralNotice(event, "❌ An error occurred. Please try again later.");
        }
    }

    // Shows a short ephemeral status embed ("Sent in dm" / error) on the
    // deferred reply, then auto-removes it after 30s so it stays clean and
    // private. Green when the text starts with ✅, red otherwise.
    private void ephemeralNotice(SlashCommandInteractionEvent event, String text) {
        EmbedBuilder embed = new EmbedBuilder()
                .setColor(Color.decode(text.startsWith("✅") ? "#2ecc71" : "#e74c3c"))
                .setDescription(text);
        event.getHook().editOriginalEmbeds(embed.build()).queue(
                ok -> event.getHook().deleteOriginal().queueAfter(30, TimeUnit.SECONDS, null, t -> {}),
                err -> {});
    }

    @Override
    public String getName() {
        return "beta-download";
    }

    @Override
    public String getDescription() {
        return "Download the Whip loader (beta)";
    }
}