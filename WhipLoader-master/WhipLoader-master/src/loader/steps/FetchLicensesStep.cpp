#pragma optimize("", off)
#include "loader/Loader.h"
#include "network/WhipNexusClient.h"

void Loader::stepFetchLicenses() {
    char username[128];
    nexusClient->getUsername(username, sizeof(username));
    ctx.username = username;

    int32_t productCount = nexusClient->getProductCount();
    ctx.availableProducts.clear();

    for (int32_t i = 0; i < productCount; ++i) {
        auto product = nexusClient->getProduct(i);
        ctx.availableProducts.push_back(product);
    }

    if (ctx.availableProducts.empty()) {
        handleError(Error(ErrorCode::InvalidData, "No products available"), false);
        return;
    }

    ctx.selectedProductIndex = 0;
    transitionTo(LoaderStep::SelectingProduct, "Selecting product...");
}
#pragma optimize("", on)
