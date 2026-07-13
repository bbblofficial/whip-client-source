package fr.whip.bot.manager.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class CryptoManager {

    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoManager.class);

    private final Map<String, Double> prices = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public CryptoManager() {
        // Fail-safe defaults to avoid 0.0 at all costs
        prices.put("BTCEUR", 60000.0);
        prices.put("LTCEUR", 80.0);
        prices.put("ETHEUR", 3200.0);
        prices.put("SOLEUR", 150.0);
        prices.put("EURUSDT", 1.08);
    }

    public void start() {
        LOGGER.info("Starting CryptoManager and performing initial synchronous price fetch...");
        // Initial synchronous update to ensure map is populated before bot fully starts
        updatePricesSync();

        // Schedule every minute for future updates
        scheduler.scheduleAtFixedRate(this::updatePrices, 1, 1, TimeUnit.MINUTES);
    }

    private void updatePricesSync() {
        // Fetch EURUSDT first as it's used for fallbacks
        fetchPriceSync("EURUSDT");

        fetchPriceSync("BTCEUR", "BTCUSDT");
        fetchPriceSync("LTCEUR", "LTCUSDT");
        fetchPriceSync("ETHEUR", "ETHUSDT");
        fetchPriceSync("SOLEUR", "SOLUSDT");
    }

    private void updatePrices() {
        fetchPrice("EURUSDT");

        fetchPrice("BTCEUR", "BTCUSDT");
        fetchPrice("LTCEUR", "LTCUSDT");
        fetchPrice("ETHEUR", "ETHUSDT");
        fetchPrice("SOLEUR", "SOLUSDT");
    }

    private void fetchPriceSync(String symbol) {
        fetchPriceSync(symbol, null);
    }

    private void fetchPriceSync(String symbol, String fallbackSymbol) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.binance.com/api/v3/ticker/price?symbol=" + symbol))
                    .GET()
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                handlePriceResponse(symbol, response.body());
            } else if (fallbackSymbol != null) {
                fetchPriceSync(fallbackSymbol, null);
            }
        } catch (Exception e) {
            LOGGER.error("Synchronous price fetch failed for {}: {}", symbol, e.getMessage());
            if (fallbackSymbol != null) {
                fetchPriceSync(fallbackSymbol, null);
            }
        }
    }

    private void fetchPrice(String symbol) {
        fetchPrice(symbol, null);
    }

    private void fetchPrice(String symbol, String fallbackSymbol) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.binance.com/api/v3/ticker/price?symbol=" + symbol))
                .GET()
                .build();

        HTTP_CLIENT.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(resp -> {
                    if (resp.statusCode() != 200) {
                        if (fallbackSymbol != null) {
                            LOGGER.warn("Failed to fetch primary price for {}: HTTP {}. Trying fallback {}...", symbol,
                                    resp.statusCode(), fallbackSymbol);
                            fetchPrice(fallbackSymbol, null);
                        } else if (!symbol.equals("EURUSDT")) {
                            LOGGER.warn("Failed to fetch price for {}: HTTP {}", symbol, resp.statusCode());
                        }
                        return null;
                    }
                    return resp.body();
                })
                .thenAccept(body -> {
                    if (body != null) {
                        handlePriceResponse(symbol, body);
                    }
                })
                .exceptionally(ex -> {
                    LOGGER.error("Async error fetching price for {}: {}", symbol, ex.getMessage());
                    return null;
                });
    }

    private void handlePriceResponse(String symbol, String body) {
        try {
            JsonNode node = OBJECT_MAPPER.readTree(body);
            double price = node.get("price").asDouble();
            if (price > 0) {
                if (symbol.endsWith("USDT") && !symbol.equals("EURUSDT")) {
                    // Convert USDT price to EUR using the latest EURUSDT rate
                    double eurUsdt = prices.getOrDefault("EURUSDT", 1.08);
                    double eurPrice = price / eurUsdt;
                    prices.put(symbol.replace("USDT", "EUR"), eurPrice);
                    LOGGER.info("Updated {} via fallback {} (Rate: {})", symbol.replace("USDT", "EUR"), symbol,
                            eurPrice);
                } else {
                    prices.put(symbol, price);
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error parsing price for {}: {}", symbol, e.getMessage());
        }
    }

    public double getPrice(String symbol) {
        return prices.getOrDefault(symbol, 0.0);
    }

    public void stop() {
        scheduler.shutdown();
    }
}
