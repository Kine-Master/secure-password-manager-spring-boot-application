package com.example.secure_password_manager_app.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for authentication (login/registration) responses.
 * Contains the JWT token and potentially other user details.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {

    private String token;
    private String refreshToken; // need this line
    private String message;
    private String role;
    private Long userId;
}