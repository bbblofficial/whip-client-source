package fr.whip.api.model;

public enum UserGrade {
    user,
    media,
    moderator,
    admin,
    owner;

    public int getLevel() {
        return ordinal();
    }

    public boolean isAtLeast(UserGrade required) {
        return this.ordinal() >= required.ordinal();
    }
}
