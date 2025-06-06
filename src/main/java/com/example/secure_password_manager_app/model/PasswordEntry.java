package com.example.secure_password_manager_app.model;

import jakarta.persistence.*; // NEW IMPORT: For JPA annotations
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime; // NEW IMPORT: For LocalDateTime

/**
 * Represents a single password entry stored by a user.
 * Each entry is linked to a specific user.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "password_entries") // Recommended table name
public class PasswordEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String label; // e.g., "Google Account", "Work VPN"

    @Column(nullable = false)
    private String username; // The username for the stored account

    @Column(nullable = false, length = 1024) // Increase length for encrypted data
    private String encryptedPassword; // The encrypted password

    private String url; // Optional URL for the service

    @Column(length = 500) // Optional description
    private String description;

    // --- RBAC Implementation: Link to User ---
    @ManyToOne(fetch = FetchType.LAZY) // Many password entries can belong to one user
    @JoinColumn(name = "user_id", nullable = false) // Foreign key column
    private User user; // The user who owns this password entry

    // --- Audit Fields ---
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt; // Timestamp when the entry was created

    // You might also add a lastUpdated field if needed:
    // private LocalDateTime lastUpdated;

    // Note: No 'plainPassword' field here. The DTO handles plain text before encryption.
}