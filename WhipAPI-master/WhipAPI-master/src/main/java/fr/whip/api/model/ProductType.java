package fr.whip.api.model;

import lombok.Getter;

@Getter
public enum ProductType {

    WHIP_CLIENT("whip-client", "Whip Client"),
    WHIP_LITE("whip-lite", "Whip Lite"),
    WHIP_AUTOCLICKER("whip-autoclicker", "Whip Autoclicker"),
    WHIP_BYPASS("whip-bypass", "Whip Bypass"),
    ;

    private final String code;
    private final String displayName;

    ProductType(String code, String displayName) {
        this.code = code;
        this.displayName = displayName;
    }
}
