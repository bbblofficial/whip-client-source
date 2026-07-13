package gg.whip.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@SpringBootApplication
@EnableScheduling
@ConfigurationPropertiesScan
@EntityScan(basePackages = {"gg.whip.server", "fr.whip.api.model"})
public class WhipServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(WhipServerApplication.class, args);
    }

    // Dedicated thread pool for heavy file download work (read + compress + chunk).
    // Running downloads on the Netty I/O thread blocks the event loop for 3-4s,
    // preventing any other packet (e.g. REVERSE_DETECTED) from being processed.
    @Bean(name = "downloadExecutor")
    public ExecutorService downloadExecutor() {
        return Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "download-worker");
            t.setDaemon(true);
            return t;
        });
    }
}