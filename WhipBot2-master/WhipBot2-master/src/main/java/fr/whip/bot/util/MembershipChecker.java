package fr.whip.bot.util;

import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.entities.Guild;
import net.dv8tion.jda.api.entities.User;

import java.util.List;

/**
 * Checks whether a user is a member of at least one guild the bot is in
 * (the Whip servers). The member cache is consulted first; uncached users
 * are resolved with REST lookups, one guild at a time.
 */
public final class MembershipChecker {

    private MembershipChecker() {
    }

    public static void check(JDA jda, User user, Runnable onMember, Runnable onNotMember) {
        List<Guild> guilds = jda.getGuilds();
        if (guilds.isEmpty()) {
            // No guild to check against (misconfigured/starting up) — fail open,
            // matching the previous behavior when the main guild was unresolvable.
            onMember.run();
            return;
        }

        for (Guild guild : guilds) {
            if (guild.isMember(user)) {
                onMember.run();
                return;
            }
        }

        retrieveNext(guilds, 0, user, onMember, onNotMember);
    }

    private static void retrieveNext(List<Guild> guilds, int index, User user,
                                     Runnable onMember, Runnable onNotMember) {
        if (index >= guilds.size()) {
            onNotMember.run();
            return;
        }
        guilds.get(index).retrieveMember(user).queue(
                member -> onMember.run(),
                err -> retrieveNext(guilds, index + 1, user, onMember, onNotMember));
    }
}
