package fr.whip.bot.command.impl;

import fr.whip.api.model.Download;
import fr.whip.api.model.License;
import fr.whip.api.model.Product;
import fr.whip.api.model.User;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.data.ConfigData;
import fr.whip.bot.manager.impl.DownloadManager;
import fr.whip.bot.manager.impl.LicenseManager;
import fr.whip.bot.manager.impl.UserManager;
import fr.whip.bot.service.FileHostingService;
import fr.whip.bot.util.LoaderPatcher;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.utils.FileUpload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;

public record DownloadCommand(
        UserManager userManager,
        LicenseManager licenseManager,
        DownloadManager downloadManager,
        ConfigData configData,
        FileHostingService fileHostingService
) implements IParentCommand {

    private static final Logger LOGGER = LoggerFactory.getLogger(DownloadCommand.class);

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        if (event.getMember() == null) {
            return;
        }

        String discordId = event.getMember().getId();

        User user = userManager.findByDiscordId(discordId).orElse(null);
        if (user == null) {
            event.reply("You need to register first! Use `/register` with a valid license key.")
                    .setEphemeral(true).queue();
            return;
        }

        List<License> licenses = licenseManager.findByUser(user);
        if (licenses.isEmpty()) {
            event.reply("You don't have any active licenses.")
                    .setEphemeral(true).queue();
            return;
        }

        License activeLicense = licenses.stream()
                .filter(License::isValid)
                .findFirst()
                .orElse(null);

        if (activeLicense == null) {
            event.reply("You don't have any active licenses. All your licenses have expired or been revoked.")
                    .setEphemeral(true).queue();
            return;
        }

        Product product = activeLicense.getProduct();
        if (product == null) {
            event.reply("Your license is not associated with any product. Please contact an administrator.")
                    .setEphemeral(true).queue();
            return;
        }

        if (!configData.loaderPath().exists()) {
            event.reply("The loader is currently unavailable. Please contact an administrator.")
                    .setEphemeral(true).queue();
            return;
        }

        event.deferReply(true).queue();

        try {
            downloadManager.revokeAllForUserAndProduct(user, product);

            String downloadId = downloadManager.generateDownloadId();
            byte[] patchedLoader = LoaderPatcher.patchLoader(
                    configData.loaderPath(),
                    downloadId
            );

            Download download = new Download();
            download.setDownloadId(downloadId);
            download.setUser(user);
            download.setProduct(product);
            download.setDownloadedAt(Instant.now());
            downloadManager.save(download);

            String fileName = LoaderPatcher.generateFileName();

            if (fileHostingService != null && configData.fileHosting().enabled()) {
                String downloadUrl = fileHostingService.createTemporaryLink(patchedLoader, fileName);

                event.getHook().editOriginal(
                        "✅ **Your loader is ready!**\n\n" +
                        "🔗 Download link: " + downloadUrl + "\n\n" +
                        "⚠️ **This link expires in 1 minute and can only be used once!**"
                ).queue();

                LOGGER.info("Download {} link created for user {} ({}) for product {}",
                        downloadId, user.getUsername(), discordId, product.getName());
            } else {
                event.getUser().openPrivateChannel().queue(channel -> {
                    channel.sendFiles(FileUpload.fromData(patchedLoader, fileName)).queue(
                            success -> {
                                event.getHook().editOriginal("Your loader has been sent to your DMs!").queue();
                                LOGGER.info("Download {} sent to user {} ({}) for product {}",
                                        downloadId, user.getUsername(), discordId, product.getName());
                            },
                            error -> {
                                event.getHook().editOriginal("Failed to send the loader. Make sure your DMs are open!")
                                        .queue();
                                LOGGER.error("Failed to send download to user {}", discordId, error);
                            }
                    );
                }, error -> {
                    event.getHook().editOriginal("Cannot open DM channel. Please enable DMs from server members!")
                            .queue();
                });
            }

        } catch (Exception e) {
            LOGGER.error("Error processing download for user {}", discordId, e);
            event.getHook().editOriginal("An error occurred while preparing your download. Please try again later.")
                    .queue();
        }
    }

    @Override
    public String getName() {
        return "download";
    }

    @Override
    public String getDescription() {
        return "Download the loader for your licensed products";
    }
}