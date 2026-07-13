package fr.whip.bot.listener;

import at.favre.lib.crypto.bcrypt.BCrypt;
import fr.whip.bot.WhipBot;
import fr.whip.bot.command.impl.RulesCommand;
import fr.whip.bot.data.log.LogCategory;
import fr.whip.bot.manager.impl.PasswordResetListener;
import net.dv8tion.jda.api.components.label.Label;
import net.dv8tion.jda.api.components.textinput.TextInput;
import net.dv8tion.jda.api.components.textinput.TextInputStyle;
import net.dv8tion.jda.api.entities.Role;
import net.dv8tion.jda.api.events.interaction.ModalInteractionEvent;
import net.dv8tion.jda.api.events.interaction.component.ButtonInteractionEvent;
import net.dv8tion.jda.api.events.interaction.component.GenericComponentInteractionCreateEvent;
import net.dv8tion.jda.api.modals.Modal;

import java.util.UUID;

public record ComponentListener(WhipBot main) implements Listener {

    @EventHandler
    public void onComponentInteract(GenericComponentInteractionCreateEvent event) {
        this.main.getComponentHandler().applyInteraction(event);
    }

    @EventHandler
    public void onModalInteraction(ModalInteractionEvent event) {
        if (event.getModalId().startsWith(PasswordResetListener.BUTTON_PREFIX)) {
            handlePasswordResetModal(event);
            return;
        }
        this.main.getComponentHandler().applyModalInteraction(event);
    }

    private static long parseEpoch(String s) {
        try {
            return Long.parseLong(s);
        } catch (Exception e) {
            return 0;
        }
    }

    private static boolean isExpired(long epochSeconds) {
        return epochSeconds > 0 && System.currentTimeMillis() / 1000 > epochSeconds;
    }

    // User clicked "Set my password" → open a modal to enter the new one.
    // data = "<userId>:<expiryEpoch>"
    private void handlePasswordResetButton(ButtonInteractionEvent event, String data) {
        String[] parts = data.split(":");
        String userId = parts[0];
        long expiry = parts.length > 1 ? parseEpoch(parts[1]) : 0;
        if (isExpired(expiry)) {
            event.reply("❌ This reset link has expired. Ask an admin for a new one.").setEphemeral(true).queue();
            return;
        }
        main.getUserManager().findById(UUID.fromString(userId)).ifPresentOrElse(user -> {
            if (!event.getUser().getId().equals(user.getDiscordId())) {
                event.reply("❌ This button isn't for you.").setEphemeral(true).queue();
                return;
            }
            TextInput input = TextInput.create("password", TextInputStyle.SHORT)
                    .setRequiredRange(6, 100)
                    .setPlaceholder("Your new Whip password")
                    .build();
            // Carry the originating message id so we can delete it on success.
            Modal modal = Modal.create(
                            PasswordResetListener.BUTTON_PREFIX + userId + ":" + expiry + ":" + event.getMessageId(),
                            "Reset your password")
                    .addComponents(Label.of("New password", input))
                    .build();
            event.replyModal(modal).queue();
        }, () -> event.reply("❌ Account not found.").setEphemeral(true).queue());
    }

    // modalId = "pwreset:<userId>:<expiryEpoch>:<messageId>"
    private void handlePasswordResetModal(ModalInteractionEvent event) {
        String[] parts = event.getModalId().substring(PasswordResetListener.BUTTON_PREFIX.length()).split(":");
        String userId = parts[0];
        long expiry = parts.length > 1 ? parseEpoch(parts[1]) : 0;
        String messageId = parts.length > 2 ? parts[2] : null;
        if (isExpired(expiry)) {
            event.reply("❌ This reset link has expired.").setEphemeral(true).queue();
            return;
        }
        main.getUserManager().findById(UUID.fromString(userId)).ifPresentOrElse(user -> {
            if (!event.getUser().getId().equals(user.getDiscordId())) {
                event.reply("❌ Not allowed.").setEphemeral(true).queue();
                return;
            }
            var mapping = event.getValue("password");
            String password = mapping != null ? mapping.getAsString() : "";
            if (password.length() < 6) {
                event.reply("❌ Password too short (6 characters minimum).").setEphemeral(true).queue();
                return;
            }
            String hash = BCrypt.withDefaults().hashToString(12, password.toCharArray());
            boolean ok;
            try {
                ok = main.getUserManager().updatePassword(user.getId(), hash);
            } catch (Exception e) {
                event.reply("❌ Could not update your password, please try again later.").setEphemeral(true).queue();
                return;
            }
            if (!ok) {
                event.reply("❌ Could not update your password (account not found).").setEphemeral(true).queue();
                return;
            }
            main.getLogManager().info(LogCategory.AUTH, event.getUser().getId(),
                    "Password reset via Discord for " + user.getUsername());
            main.getAuditManager().event("user.reset_password", "user", user.getId(),
                    "Password reset via Discord");
            event.reply("✅ Your Whip password has been updated.").setEphemeral(true).queue();
            // Delete the original DM message that held the button.
            if (messageId != null) {
                event.getUser().openPrivateChannel().queue(
                        pc -> pc.deleteMessageById(messageId).queue(s -> {}, t -> {}));
            }
        }, () -> event.reply("❌ Account not found.").setEphemeral(true).queue());
    }

    @EventHandler
    public void onButtonInteract(ButtonInteractionEvent event) {
        String id = event.getComponentId();

        if (id.equals(RulesCommand.ACCEPT_BUTTON_ID) || id.equals(RulesCommand.CUSTOMER_BUTTON_ID)) {
            if (event.getGuild() == null || event.getMember() == null) {
                event.reply("❌ Guild only.").setEphemeral(true).queue();
                return;
            }
            long roleId = id.equals(RulesCommand.CUSTOMER_BUTTON_ID)
                    ? RulesCommand.CUSTOMER_ROLE_ID
                    : RulesCommand.RULES_ROLE_ID;
            Role role = event.getGuild().getRoleById(roleId);
            if (role == null) {
                event.reply("❌ Role not configured.").setEphemeral(true).queue();
                return;
            }
            if (event.getMember().getRoles().contains(role)) {
                event.reply("✅ You already accepted the rules.").setEphemeral(true).queue();
                return;
            }
            event.getGuild().addRoleToMember(event.getMember(), role).queue(
                    success -> event.reply("✅ Rules accepted, role granted!").setEphemeral(true).queue(),
                    err -> event.reply("❌ Could not assign the role: " + err.getMessage()).setEphemeral(true).queue());
            return;
        }

        if (id.startsWith("ticket:close:")) {
            String userId = id.substring("ticket:close:".length());
            if (!event.getUser().getId().equals(userId)) {
                event.reply("❌ This button is not for you.").setEphemeral(true).queue();
                return;
            }
            event.deferEdit().queue();
            main.getTicketManager().findByUserDiscordId(userId).ifPresentOrElse(
                    ticket -> main.getTicketManager().closeTicket(event.getJDA(), ticket, false),
                    () -> event.getHook().editOriginal("❌ You don't have an open ticket.").queue());
            return;
        }

        if (id.startsWith(PasswordResetListener.BUTTON_PREFIX)) {
            handlePasswordResetButton(event, id.substring(PasswordResetListener.BUTTON_PREFIX.length()));
            return;
        }

        this.main.getComponentHandler().applyInteraction(event);
    }
}
