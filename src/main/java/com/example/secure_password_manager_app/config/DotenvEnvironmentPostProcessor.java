package com.example.secure_password_manager_app.config;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.io.File; // Ensure this import is present
import java.util.HashMap;
import java.util.Map;

/**
 * An EnvironmentPostProcessor that loads properties from a .env file into the Spring environment.
 * This allows managing environment variables for local development outside of application.properties/yml.
 */
public class DotenvEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final String DOTENV_FILE = ".env";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        // Check if .env file exists in the current working directory
        File dotenvFile = new File(DOTENV_FILE);
        if (dotenvFile.exists()) {
            System.out.println("Loading environment variables from .env file."); // For debugging
            Dotenv dotenv = Dotenv.load();
            Map<String, Object> dotenvProperties = new HashMap<>();
            dotenv.entries().forEach(entry -> dotenvProperties.put(entry.getKey(), entry.getValue()));

            // Add these properties to the Spring environment with a high precedence
            environment.getPropertySources().addFirst(new MapPropertySource("dotenvProperties", dotenvProperties));
        } else {
            System.out.println("No .env file found. Skipping dotenv loading."); // For debugging
        }
    }
}