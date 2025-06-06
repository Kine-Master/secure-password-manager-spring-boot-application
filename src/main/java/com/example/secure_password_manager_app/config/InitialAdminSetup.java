package com.example.secure_password_manager_app.config;

import com.example.secure_password_manager_app.auth.AuthProvider;
import com.example.secure_password_manager_app.model.User;
import com.example.secure_password_manager_app.repository.UserRepository;
import com.example.secure_password_manager_app.role.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value; // NEW IMPORT: For @Value annotation
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Initializes a default admin user if no users exist in the database on application startup.
 * Admin credentials are now loaded from application.properties.
 */
@Component
@RequiredArgsConstructor
public class InitialAdminSetup implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Inject admin details from application.properties
    @Value("${app.admin.username}")
    private String adminUsername;
    @Value("${app.admin.password}")
    private String adminPassword;
    @Value("${app.admin.fullname}")
    private String adminFullName;
    @Value("${app.admin.email}")
    private String adminEmail;


    @Override
    public void run(String... args) throws Exception {
        // Check if any users exist in the database
        if (userRepository.count() == 0) {
            createInitialAdminUser();
        }
    }

    private void createInitialAdminUser() {
        // Check again to prevent race condition (though count() == 0 usually sufficient)
        if (userRepository.findByUsername(adminUsername).isEmpty() && userRepository.findByEmail(adminEmail).isEmpty()) {
            Set<Role> adminRoles = new HashSet<>();
            adminRoles.add(Role.USER); // Admins are also users
            adminRoles.add(Role.ADMIN);

            User adminUser = User.builder()
                    .username(adminUsername)
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword)) // Hash the password
                    .fullName(adminFullName)
                    .authProvider(AuthProvider.LOCAL) // This is a local admin user
                    .roles(adminRoles)
                    .createdAt(LocalDateTime.now())
                    .lastLogin(LocalDateTime.now())
                    .build();

            userRepository.save(adminUser);
            System.out.println("Initial admin user created successfully:");
            System.out.println("Username: " + adminUsername);
            System.out.println("Password: " + adminPassword); // Display for initial setup
            System.out.println("Email: " + adminEmail);
        }
    }
}