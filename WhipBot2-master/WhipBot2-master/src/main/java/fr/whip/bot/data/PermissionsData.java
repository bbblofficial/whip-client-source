package fr.whip.bot.data;

import java.util.List;

public record PermissionsData(
        String singerieUserId,
        List<String> ownerRoleIds,
        String supportRoleId,
        String customerRoleId,
        String betaRoleId) {

    public PermissionsData {
        if (singerieUserId == null) singerieUserId = "";
        if (ownerRoleIds == null) ownerRoleIds = List.of();
        if (supportRoleId == null) supportRoleId = "";
        if (customerRoleId == null) customerRoleId = "";
        if (betaRoleId == null) betaRoleId = "";
    }
}
