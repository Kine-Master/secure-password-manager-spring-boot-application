package com.example.secure_password_manager_app.controller;

import com.example.secure_password_manager_app.auth.AuthenticationRequest;
import com.example.secure_password_manager_app.auth.AuthenticationResponse;
import com.example.secure_password_manager_app.auth.RegisterRequest;
import com.example.secure_password_manager_app.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for authentication operations.
 * Handles local user registration and login.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Endpoint for local user registration.
     * Maps to POST /api/v1/auth/register.
     * @param request The registration request payload.
     * @return ResponseEntity with JWT token upon successful registration.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        AuthenticationResponse response = authService.register(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED); // 201 Created
    }

    /**
     * Endpoint for local user authentication (login).
     * Maps to POST /api/v1/auth/authenticate.
     * @param request The authentication request payload.
     * @return ResponseEntity with JWT token upon successful authentication.
     */
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        AuthenticationResponse response = authService.authenticate(request);
        return ResponseEntity.ok(response); // 200 OK
    }

    // Google OAuth2 login initiation is handled by Spring Security's default endpoint:
    // GET /oauth2/authorization/google (this will be a link on your frontend)
    // The redirect after successful login (to /oauth2/redirect on frontend with token)
    // is handled by OAuth2AuthenticationSuccessHandler on the backend.
}