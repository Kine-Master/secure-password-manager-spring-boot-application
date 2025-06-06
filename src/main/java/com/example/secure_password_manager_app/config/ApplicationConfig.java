package com.example.secure_password_manager_app.config;

import com.example.secure_password_manager_app.repository.UserRepository;
import com.example.secure_password_manager_app.security.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Global application configuration for Spring Beans, especially security-related ones.
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository; // Inject UserRepository for CustomUserDetailsService

    // Defines the UserDetailsService for local authentication
    @Bean
    public UserDetailsService userDetailsService() {
        // We use our custom implementation to load users from the database by username
        return new CustomUserDetailsService(userRepository);
    }

    // Configures the AuthenticationProvider for local authentication.
    // It uses the UserDetailsService and PasswordEncoder.
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    // Provides the AuthenticationManager. This bean is used by the AuthController
    // to authenticate users.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // Defines the PasswordEncoder. BCrypt is recommended for password hashing.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}