package com.example.secure_password_manager_app.dto.user;

import com.example.secure_password_manager_app.auth.AuthProvider;
import com.example.secure_password_manager_app.role.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * DTO for sending user data to the frontend.
 * Excludes sensitive information like passwords.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponseDto {
    private Long id;
    private String username; // This is the 'email' for local users, or derived from OAuth2 for Google users
    private String email;
    private String fullName;
    private AuthProvider authProvider;
    private Set<Role> roles;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;
}