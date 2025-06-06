package com.example.secure_password_manager_app.controller;

import com.example.secure_password_manager_app.dto.user.PasswordChangeRequest;
import com.example.secure_password_manager_app.dto.user.UserProfileUpdateDto;
import com.example.secure_password_manager_app.dto.user.UserResponseDto;
import com.example.secure_password_manager_app.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST Controller for user management operations.
 * Includes endpoints for profile viewing, updating, password changes, and admin-level user management.
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * Helper method to get the current authenticated user's ID.
     * This relies on the UserDetails object (which is our custom User model).
     */
    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            // This should ideally not happen if security is configured correctly,
            // as this endpoint is protected.
            throw new IllegalStateException("User is not authenticated.");
        }
        // Assuming your User model implements UserDetails and holds the ID
        com.example.secure_password_manager_app.model.User currentUser =
                (com.example.secure_password_manager_app.model.User) authentication.getPrincipal();
        return currentUser.getId();
    }

    /**
     * Get details of the currently authenticated user.
     * Maps to GET /api/v1/users/me
     * @return UserResponseDto of the current user.
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> getCurrentUser() {
        Long userId = getCurrentUserId();
        UserResponseDto userDto = userService.getUserById(userId);
        return ResponseEntity.ok(userDto);
    }

    /**
     * Update the profile of the currently authenticated user.
     * Maps to PUT /api/v1/users/me
     * @param updateDto DTO with fields to update (e.g., fullName).
     * @return UserResponseDto of the updated user.
     */
    @PutMapping("/me")
    public ResponseEntity<UserResponseDto> updateCurrentUserProfile(
            @RequestBody UserProfileUpdateDto updateDto
    ) {
        Long userId = getCurrentUserId();
        UserResponseDto updatedUser = userService.updateProfile(userId, updateDto);
        return ResponseEntity.ok(updatedUser);
    }

    /**
     * Allow the currently authenticated user to change their password.
     * This endpoint will internally enforce that only LOCAL users can change passwords.
     * Maps to PUT /api/v1/users/me/password
     * @param request PasswordChangeRequest containing current and new password.
     * @return ResponseEntity indicating success or failure.
     */
    @PutMapping("/me/password")
    public ResponseEntity<String> changeCurrentUserPassword(
            @RequestBody PasswordChangeRequest request
    ) {
        Long userId = getCurrentUserId();
        userService.changePassword(userId, request); // Service layer handles the AuthProvider check
        return ResponseEntity.ok("Password changed successfully.");
    }

    // --- Admin-specific endpoints ---

    /**
     * Get details of a specific user by ID (Admin only).
     * Maps to GET /api/v1/users/{userId}
     * @param userId The ID of the user to fetch.
     * @return UserResponseDto of the requested user.
     */
    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')") // Only users with ADMIN role can access this
    public ResponseEntity<UserResponseDto> getUserById(@PathVariable Long userId) {
        UserResponseDto userDto = userService.getUserById(userId);
        return ResponseEntity.ok(userDto);
    }

    /**
     * Get all users (Admin only).
     * Maps to GET /api/v1/users
     * @return List of UserResponseDto for all users.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')") // Only users with ADMIN role can access this
    public ResponseEntity<List<UserResponseDto>> getAllUsers() {
        List<UserResponseDto> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    /**
     * Delete a user by ID (Admin only).
     * Maps to DELETE /api/v1/users/{userId}
     * @param userId The ID of the user to delete.
     * @return ResponseEntity with no content.
     */
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')") // Only users with ADMIN role can access this
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        userService.deleteUser(userId);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT); // 204 No Content
    }
}