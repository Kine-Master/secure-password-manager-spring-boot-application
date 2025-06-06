package com.example.secure_password_manager_app.controller;

import com.example.secure_password_manager_app.dto.passwordentry.PasswordEntryDto;
import com.example.secure_password_manager_app.dto.passwordentry.PasswordEntryResponseDto;
import com.example.secure_password_manager_app.service.PasswordEntryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST Controller for managing password entries.
 * Handles creation, retrieval, update, and deletion of password entries
 * for the authenticated user.
 */
@RestController
@RequestMapping("/api/v1/password-entries")
@RequiredArgsConstructor
public class PasswordEntryController {

    private final PasswordEntryService passwordEntryService;

    /**
     * Helper method to get the current authenticated user's ID.
     */
    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalStateException("User is not authenticated.");
        }
        // Assuming your User model implements UserDetails and holds the ID
        com.example.secure_password_manager_app.model.User currentUser =
                (com.example.secure_password_manager_app.model.User) authentication.getPrincipal();
        return currentUser.getId();
    }

    /**
     * Create a new password entry for the authenticated user.
     * Maps to POST /api/v1/password-entries
     * @param entryDto DTO containing the details of the password entry (with plain password).
     * @return ResponseEntity with the created password entry (decrypted).
     */
    @PostMapping
    public ResponseEntity<PasswordEntryResponseDto> createPasswordEntry(
            @RequestBody PasswordEntryDto entryDto
    ) {
        Long userId = getCurrentUserId();
        PasswordEntryResponseDto createdEntry = passwordEntryService.createPasswordEntry(userId, entryDto);
        return new ResponseEntity<>(createdEntry, HttpStatus.CREATED); // 201 Created
    }

    /**
     * Get a specific password entry by ID for the authenticated user.
     * The password will be decrypted by the service layer.
     * Maps to GET /api/v1/password-entries/{id}
     * @param id The ID of the password entry.
     * @return ResponseEntity with the password entry (decrypted).
     */
    @GetMapping("/{id}")
    public ResponseEntity<PasswordEntryResponseDto> getPasswordEntryById(@PathVariable Long id) {
        Long userId = getCurrentUserId();
        PasswordEntryResponseDto entry = passwordEntryService.getPasswordEntryById(id, userId);
        return ResponseEntity.ok(entry); // 200 OK
    }

    /**
     * Get all password entries for the authenticated user.
     * All passwords will be decrypted by the service layer.
     * Maps to GET /api/v1/password-entries
     * @return ResponseEntity with a list of password entries (decrypted).
     */
    @GetMapping
    public ResponseEntity<List<PasswordEntryResponseDto>> getAllPasswordEntries() {
        Long userId = getCurrentUserId();
        List<PasswordEntryResponseDto> entries = passwordEntryService.getAllPasswordEntriesForUser(userId);
        return ResponseEntity.ok(entries); // 200 OK
    }

    /**
     * Update an existing password entry for the authenticated user.
     * The new plain password (if provided) will be encrypted by the service layer.
     * Maps to PUT /api/v1/password-entries/{id}
     * @param id The ID of the password entry to update.
     * @param entryDto DTO containing the updated details (with potential new plain password).
     * @return ResponseEntity with the updated password entry (decrypted).
     */
    @PutMapping("/{id}")
    public ResponseEntity<PasswordEntryResponseDto> updatePasswordEntry(
            @PathVariable Long id,
            @RequestBody PasswordEntryDto entryDto
    ) {
        Long userId = getCurrentUserId();
        PasswordEntryResponseDto updatedEntry = passwordEntryService.updatePasswordEntry(id, userId, entryDto);
        return ResponseEntity.ok(updatedEntry); // 200 OK
    }

    /**
     * Delete a password entry for the authenticated user.
     * Maps to DELETE /api/v1/password-entries/{id}
     * @param id The ID of the password entry to delete.
     * @return ResponseEntity with no content.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePasswordEntry(@PathVariable Long id) {
        Long userId = getCurrentUserId();
        passwordEntryService.deletePasswordEntry(id, userId);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT); // 204 No Content
    }
}