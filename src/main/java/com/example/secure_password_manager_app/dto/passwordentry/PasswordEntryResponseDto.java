package com.example.secure_password_manager_app.dto.passwordentry;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for sending password entry data to the frontend.
 * The 'decryptedPassword' field is populated only when explicitly requested/authorized.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordEntryResponseDto {
    private Long id;
    private String label;
    private String username;
    private String url;
    private String description;
    private String decryptedPassword; // Populated only when the client requests decryption
    private Long userId; // To identify the owner of the entry
}