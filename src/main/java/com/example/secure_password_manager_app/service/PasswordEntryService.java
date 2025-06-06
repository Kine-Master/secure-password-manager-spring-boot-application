package com.example.secure_password_manager_app.service;

import com.example.secure_password_manager_app.dto.passwordentry.PasswordEntryDto;
import com.example.secure_password_manager_app.dto.passwordentry.PasswordEntryResponseDto;
import com.example.secure_password_manager_app.exception.ResourceNotFoundException;
import com.example.secure_password_manager_app.model.PasswordEntry;
import com.example.secure_password_manager_app.model.User;
import com.example.secure_password_manager_app.repository.PasswordEntryRepository;
import com.example.secure_password_manager_app.repository.UserRepository;
import com.example.secure_password_manager_app.security.AesSecurity;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Service class for managing password entries, including encryption and decryption.
 * Ensures that users can only manage their own password entries.
 */
@Service
@RequiredArgsConstructor
public class PasswordEntryService {

    private final PasswordEntryRepository passwordEntryRepository;
    private final UserRepository userRepository;
    private final AesSecurity aesSecurity; // Our AES encryption/decryption utility

    /**
     * Creates a new password entry for a specific user.
     * The plain password from the DTO is encrypted before saving.
     *
     * @param userId The ID of the user creating the entry.
     * @param entryDto The DTO containing the password entry details (with plain password).
     * @return PasswordEntryResponseDto of the created entry with decrypted password.
     * @throws ResourceNotFoundException if the user is not found.
     */
    @Transactional
    public PasswordEntryResponseDto createPasswordEntry(Long userId, PasswordEntryDto entryDto) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        // Encrypt the plain password before saving
        String encryptedPassword = aesSecurity.encrypt(entryDto.getPlainPassword());

        PasswordEntry passwordEntry = PasswordEntry.builder()
                .label(entryDto.getLabel())
                .username(entryDto.getUsername())
                .encryptedPassword(encryptedPassword) // Store the encrypted password
                .url(entryDto.getUrl())
                .description(entryDto.getDescription())
                .user(user) // Link the entry to the user
                .build();

        PasswordEntry savedEntry = passwordEntryRepository.save(passwordEntry);
        return mapToResponseDto(savedEntry, true); // Return with decrypted password as it's newly created
    }

    /**
     * Retrieves a specific password entry by its ID for a given user.
     * The encrypted password is decrypted before being returned in the DTO.
     *
     * @param entryId The ID of the password entry to retrieve.
     * @param userId The ID of the user who owns the entry.
     * @return PasswordEntryResponseDto with the decrypted password.
     * @throws ResourceNotFoundException if the entry is not found or does not belong to the user.
     */
    public PasswordEntryResponseDto getPasswordEntryById(Long entryId, Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        PasswordEntry passwordEntry = passwordEntryRepository.findByIdAndUser(entryId, user)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found or not owned by user with id: " + entryId));

        // Decrypt the password as per your requirement
        return mapToResponseDto(passwordEntry, true);
    }

    /**
     * Retrieves all password entries for a specific user.
     * All encrypted passwords are decrypted before being returned in the DTOs.
     *
     * @param userId The ID of the user whose entries to retrieve.
     * @return A list of PasswordEntryResponseDto with decrypted passwords.
     * @throws ResourceNotFoundException if the user is not found.
     */
    public List<PasswordEntryResponseDto> getAllPasswordEntriesForUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        List<PasswordEntry> entries = passwordEntryRepository.findByUser(user);

        // Decrypt each password entry as per your requirement
        return entries.stream()
                .map(entry -> mapToResponseDto(entry, true)) // Always decrypt when fetching for user
                .collect(Collectors.toList());
    }

    /**
     * Updates an existing password entry for a specific user.
     * The plain password from the DTO is encrypted before saving.
     *
     * @param entryId The ID of the password entry to update.
     * @param userId The ID of the user who owns the entry.
     * @param entryDto The DTO containing updated password entry details (with plain password).
     * @return PasswordEntryResponseDto of the updated entry with decrypted password.
     * @throws ResourceNotFoundException if the entry is not found or does not belong to the user.
     */
    @Transactional
    public PasswordEntryResponseDto updatePasswordEntry(Long entryId, Long userId, PasswordEntryDto entryDto) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        PasswordEntry existingEntry = passwordEntryRepository.findByIdAndUser(entryId, user)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found or not owned by user with id: " + entryId));

        // Update fields
        existingEntry.setLabel(entryDto.getLabel());
        existingEntry.setUsername(entryDto.getUsername());
        existingEntry.setUrl(entryDto.getUrl());
        existingEntry.setDescription(entryDto.getDescription());

        // Encrypt the new plain password if provided
        if (entryDto.getPlainPassword() != null && !entryDto.getPlainPassword().isEmpty()) {
            existingEntry.setEncryptedPassword(aesSecurity.encrypt(entryDto.getPlainPassword()));
        }

        PasswordEntry updatedEntry = passwordEntryRepository.save(existingEntry);
        return mapToResponseDto(updatedEntry, true); // Return with decrypted password
    }

    /**
     * Deletes a password entry by its ID for a specific user.
     *
     * @param entryId The ID of the password entry to delete.
     * @param userId The ID of the user who owns the entry.
     * @throws ResourceNotFoundException if the entry is not found or does not belong to the user.
     */
    @Transactional
    public void deletePasswordEntry(Long entryId, Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        PasswordEntry existingEntry = passwordEntryRepository.findByIdAndUser(entryId, user)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found or not owned by user with id: " + entryId));

        passwordEntryRepository.delete(existingEntry);
    }

    /**
     * Helper method to map a PasswordEntry entity to a PasswordEntryResponseDto.
     * Decrypts the password if 'decrypt' flag is true.
     *
     * @param entry The PasswordEntry entity.
     * @param decrypt If true, the password will be decrypted for the DTO.
     * @return A new PasswordEntryResponseDto.
     */
    private PasswordEntryResponseDto mapToResponseDto(PasswordEntry entry, boolean decrypt) {
        String decryptedPassword = null;
        if (decrypt && entry.getEncryptedPassword() != null) {
            decryptedPassword = aesSecurity.decrypt(entry.getEncryptedPassword());
        }

        return PasswordEntryResponseDto.builder()
                .id(entry.getId())
                .label(entry.getLabel())
                .username(entry.getUsername())
                .url(entry.getUrl())
                .description(entry.getDescription())
                .decryptedPassword(decryptedPassword) // Populate only if decrypted
                .userId(entry.getUser().getId()) // Include user ID for context
                .build();
    }
}