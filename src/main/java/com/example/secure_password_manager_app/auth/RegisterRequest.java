package com.example.secure_password_manager_app.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for local user registration requests.
 * Contains necessary information to create a new local user account.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    private String fullName;
    private String username; // Will be mapped to email in the User entity for local users
    private String email;
    private String password;
}