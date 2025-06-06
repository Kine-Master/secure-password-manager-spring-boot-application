package com.example.secure_password_manager_app.repository;

import com.example.secure_password_manager_app.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Spring Data JPA Repository for the User entity.
 * Provides standard CRUD operations and custom query methods for user retrieval.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    // Finds a user by their username. This will be the primary identifier for local user login.
    Optional<User> findByUsername(String username);

    // Finds a user by their email. This is crucial for OAuth2 lookups and for general contact.
    Optional<User> findByEmail(String email);

    // Finds a user by their Google ID, essential for OAuth2 JIT registration and subsequent logins.
    Optional<User> findByGoogleId(String googleId);

    // Checks if a user with the given username already exists, useful during registration.
    boolean existsByUsername(String username);

    // Checks if a user with the given email already exists, useful during registration and OAuth2.
    boolean existsByEmail(String email);
}