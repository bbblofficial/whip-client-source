package gg.whip.server.service;

import gg.whip.server.data.AuthRequest;
import gg.whip.server.data.AuthResult;
import gg.whip.server.data.Product;
import gg.whip.server.service.auth.ProductAuthStrategy;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class AuthenticationService {

    private final Map<Product, ProductAuthStrategy> strategies;

    public AuthenticationService(List<ProductAuthStrategy> strategies) {
        this.strategies = strategies.stream()
                .collect(Collectors.toUnmodifiableMap(ProductAuthStrategy::product, Function.identity()));
    }

    public AuthResult authenticate(AuthRequest request) {
        Product product = Product.fromCode(request.productCode());
        if (product == null) {
            return AuthResult.failure(AuthError.NO_VALID_LICENSE);
        }

        ProductAuthStrategy strategy = strategies.get(product);
        if (strategy == null) {
            return AuthResult.failure(AuthError.NO_VALID_LICENSE);
        }

        return strategy.authenticate(request);
    }

    public enum AuthError {
        INVALID_CREDENTIALS(4, "Invalid credentials"),
        NO_VALID_LICENSE(5, "No valid license"),
        MACHINE_REVOKED(6, "Machine revoked"),
        SESSION_LIMIT_REACHED(7, "Session limit reached"),
        USER_BLACKLISTED(8, "Account blacklisted");

        private final int code;
        private final String message;

        AuthError(int code, String message) {
            this.code = code;
            this.message = message;
        }

        public int code() { return code; }
        public String message() { return message; }
    }
}
