package gg.whip.server.data;

import fr.whip.api.model.License;
import fr.whip.api.model.Machine;
import fr.whip.api.model.User;
import gg.whip.server.service.AuthenticationService;

public record AuthResult(boolean success, AuthenticationService.AuthError error, User user, License license, Machine machine) {

    public static AuthResult success(User user, License license, Machine machine) {
        return new AuthResult(true, null, user, license, machine);
    }

    public static AuthResult failure(AuthenticationService.AuthError error) {
        return new AuthResult(false, error, null, null, null);
    }
}