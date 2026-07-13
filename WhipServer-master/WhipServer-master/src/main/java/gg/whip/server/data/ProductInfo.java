package gg.whip.server.data;

import fr.whip.api.model.ProductType;

public record ProductInfo(
        ProductType code,
        String name,
        String description,
        long expiresAt,
        boolean lifetime
) {}
