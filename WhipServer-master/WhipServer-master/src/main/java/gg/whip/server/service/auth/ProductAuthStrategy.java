package gg.whip.server.service.auth;

import gg.whip.server.data.AuthRequest;
import gg.whip.server.data.AuthResult;
import gg.whip.server.data.Product;

public interface ProductAuthStrategy {

    Product product();

    AuthResult authenticate(AuthRequest request);
}
