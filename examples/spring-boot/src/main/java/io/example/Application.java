package io.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Minimal Spring Boot app demonstrating the sealed-env-spring-boot-starter.
 *
 * The starter runs as an ApplicationContextInitializer: it reads the
 * configured .env.sealed file, decrypts it using SEALED_ENV_KEY, and
 * registers each KEY=value pair as a property source so that
 * @Value("${KEY}") and Environment.getProperty("KEY") both work
 * transparently. No code change vs. plain application.properties.
 */
@SpringBootApplication
@RestController
public class Application {

    /**
     * Resolved from .env.sealed at startup.
     * No different from any other Spring property — that's the point.
     */
    @Value("${DATABASE_URL:(unset)}")
    private String databaseUrl;

    @Value("${STRIPE_KEY:(unset)}")
    private String stripeKey;

    @Value("${JWT_SECRET:(unset)}")
    private String jwtSecret;

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @GetMapping("/")
    public Map<String, Object> home() {
        return Map.of(
            "message", "sealed-env demo · Spring Boot",
            "secrets", Map.of(
                "DATABASE_URL", databaseUrl,
                "STRIPE_KEY", stripeKey,
                "JWT_SECRET", redact(jwtSecret)
            ),
            "note",
            "In a real app, never expose secrets in an HTTP response. " +
            "This endpoint exists only to prove the values were decrypted."
        );
    }

    private static String redact(String value) {
        if (value == null || value.isEmpty()) return "(unset)";
        if (value.length() < 8) return "***";
        return value.substring(0, 4) + "*".repeat(value.length() - 4);
    }
}
