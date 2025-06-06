package com.example.secure_password_manager_app.dto.passwordentry;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for creating or updating a password entry.
 * This DTO holds the plain-text password before encryption in the service layer.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordEntryDto {
    private String label;
    private String username; // Username associated with the entry (e.g., for a website)
    private String plainPassword; // The password in plain text from the client
    private String url;
    private String description;
}