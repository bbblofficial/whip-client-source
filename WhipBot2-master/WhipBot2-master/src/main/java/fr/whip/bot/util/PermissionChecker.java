package fr.whip.bot.util;

import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.entities.Member;
import net.dv8tion.jda.api.entities.Role;
import net.dv8tion.jda.api.entities.User;
import net.dv8tion.jda.api.entities.channel.middleman.MessageChannel;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.events.message.MessageReceivedEvent;

public final class PermissionChecker {

    private PermissionChecker() {}

    public static boolean isUser(User user, String userId) {
        return user != null && userId != null && !userId.isEmpty() && userId.equals(user.getId());
    }

    public static boolean hasRole(Member member, String roleId) {
        if (member == null || roleId == null || roleId.isEmpty()) return false;
        for (Role role : member.getRoles()) {
            if (roleId.equals(role.getId())) return true;
        }
        return false;
    }

    /** True if the member has the role, OR is the guild owner / an administrator. */
    public static boolean hasRoleOrAdmin(Member member, String roleId) {
        if (member == null) return false;
        if (member.isOwner() || member.hasPermission(Permission.ADMINISTRATOR)) return true;
        return hasRole(member, roleId);
    }

    public static boolean hasAnyRole(Member member, java.util.List<String> roleIds) {
        if (member == null || roleIds == null || roleIds.isEmpty()) return false;
        for (Role role : member.getRoles()) {
            if (roleIds.contains(role.getId())) return true;
        }
        return false;
    }

    public static boolean inChannel(MessageChannel channel, String channelId) {
        return channel != null && channelId != null && !channelId.isEmpty() && channelId.equals(channel.getId());
    }

    public static boolean denySlash(SlashCommandInteractionEvent event, String message) {
        event.reply(message).setEphemeral(true).queue();
        return false;
    }

    public static boolean denyPrefix(MessageReceivedEvent event) {
        event.getMessage().delete().queue(null, t -> {});
        return false;
    }
}
