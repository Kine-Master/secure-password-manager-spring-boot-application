package com.example.secure_password_manager_app.repository;

import com.example.secure_password_manager_app.model.PasswordEntry;
import com.example.secure_password_manager_app.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA Repository for the PasswordEntry entity.
 * Provides standard CRUD operations and custom query methods for password entries.
 */
@Repository
public interface PasswordEntryRepository extends JpaRepository<PasswordEntry, Long> {
    // Find all password entries associated with a specific user.
    List<PasswordEntry> findByUser(User user);

    // Find a specific password entry by its ID and ensuring it belongs to a given user.
    // This adds a layer of security to prevent users from accessing entries they don't own.
    Optional<PasswordEntry> findByIdAndUser(Long id, User user);
}