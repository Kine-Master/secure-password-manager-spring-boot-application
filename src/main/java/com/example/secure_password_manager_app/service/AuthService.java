package com.example.secure_password_manager_app.service;

import org.springframework.security.core.userdetails.UserDetails;
import com.example.secure_password_manager_app.auth.AuthenticationRequest;
import com.example.secure_password_manager_app.auth.AuthenticationResponse;
import com.example.secure_password_manager_app.auth.AuthProvider;
import com.example.secure_password_manager_app.auth.RegisterRequest;
import com.example.secure_password_manager_app.model.User;
import com.example.secure_password_manager_app.repository.UserRepository;
import com.example.secure_password_manager_app.role.Role;
import com.example.secure_password_manager_app.security.JwtService; // Assuming JwtService is the correct name
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Service class for handling user authentication and registration.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService; // Renamed from JwtTokenProvider if it was that name
    private final AuthenticationManager authenticationManager;

    /**
     * Registers a new local user.
     * Throws an exception if the username (email) already exists.
     * @param request The registration request containing user details.
     * @return AuthenticationResponse with JWT token.
     */
    public AuthenticationResponse register(RegisterRequest request) {
        // Check if username (which will be email for local users) or email already exists
        // Use request.getEmail() for both checks, as email will serve as username
        if (userRepository.existsByUsername(request.getEmail()) || userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already taken. Please use a different email or login.");
        }

        Set<Role> roles = new HashSet<>();
        roles.add(Role.USER); // Default role for new registrations is USER

        User user = User.builder()
                .fullName(request.getFullName())
                .username(request.getEmail()) // <--- CHANGE: Use email as username for local users
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // Encrypt password
                .authProvider(AuthProvider.LOCAL) // Set authentication provider as LOCAL
                .roles(roles)
                .createdAt(LocalDateTime.now())
                .lastLogin(LocalDateTime.now())
                .build();

        userRepository.save(user);

        // Generate JWT tokens for the newly registered user
        String jwtToken = jwtService.generateToken((UserDetails) user);
        String refreshToken = jwtService.generateRefreshToken((UserDetails) user); // Generate refresh token

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken) // Include refresh token
                .message("Registration successful.")
                .userId(user.getId())
                .role(user.getRoles().iterator().next().name()) // Assuming one role for simplicity or take the first
                .build();
    }

    /**
     * Authenticates a local user.
     * @param request The authentication request containing username and password.
     * @return AuthenticationResponse with JWT token.
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // Authenticate using Spring Security's AuthenticationManager
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(), // This will be the email when logging in
                        request.getPassword()
                )
        );

        // If authentication succeeds, retrieve the user details
        User user = userRepository.findByUsername(request.getEmail()) // This will use the email for lookup
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + request.getEmail()));

        // Update last login time
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        // Generate JWT tokens (access token and refresh token)
        String jwtToken = jwtService.generateToken((UserDetails) user);
        String refreshToken = jwtService.generateRefreshToken((UserDetails) user); // Generate refresh token

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken) // <--- INCLUDE THE REFRESH TOKEN HERE
                .message("Authentication successful.")
                .userId(user.getId())
                .role(user.getRoles().iterator().next().name())
                .build();
    }
}