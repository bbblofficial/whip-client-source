package fr.whip.bot.command.impl;

import at.favre.lib.crypto.bcrypt.BCrypt;
import fr.whip.api.model.User;
import fr.whip.bot.command.IParentCommand;
import fr.whip.bot.manager.impl.LicenseManager;
import fr.whip.bot.manager.impl.UserManager;
import fr.whip.bot.util.OptionUtils;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.SlashCommandData;

import java.time.Instant;

public record RegisterCommand(UserManager userManager, LicenseManager licenseManager) implements IParentCommand {

    @Override
    public void execute(SlashCommandInteractionEvent event) {
        String discordId = event.getUser().getId();

        if (userManager.findByDiscordId(discordId).isPresent()) {
            event.reply("You already have an account!").setEphemeral(true).queue();
            return;
        }

        String key = OptionUtils.getStringOption(event, "key").orElseThrow(() ->
                new IllegalArgumentException("Key is required")
        );

        licenseManager.findByLicenseKey(key).ifPresentOrElse(license -> {
            if (license.getUser() != null) {
                event.reply("This license key is already used by another account!").setEphemeral(true).queue();
                return;
            }

            String username = OptionUtils.getStringOption(event, "username").orElseThrow(() ->
                    new IllegalArgumentException("Username is required")
            );
            String password = OptionUtils.getStringOption(event, "password").orElseThrow(() ->
                    new IllegalArgumentException("Password is required")
            );

            String passwordHash = BCrypt.withDefaults().hashToString(12, password.toCharArray());
            User user = new User();
            user.setUsername(username);
            user.setPasswordHash(passwordHash);
            user.setDiscordId(discordId);
            user.setCreatedAt(Instant.now());

            userManager.save(user);

            license.setUser(user);
            licenseManager.save(license);

            event.reply("Account registered successfully! Welcome, **" + username + "**!").setEphemeral(true).queue();
        }, () -> event.reply("License not found.").setEphemeral(true).queue());
    }

    @Override
    public SlashCommandData build(SlashCommandData data) {
        return data
                .addOption(OptionType.STRING, "key", "The key gift by admin", true)
                .addOption(OptionType.STRING, "username", "Your username", true)
                .addOption(OptionType.STRING, "password", "Your password", true);
    }

    @Override
    public String getName() {
        return "register";
    }

    @Override
    public String getDescription() {
        return "Command to register your account";
    }
}