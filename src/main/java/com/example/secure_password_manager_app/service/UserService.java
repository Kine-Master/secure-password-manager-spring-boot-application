package com.example.secure_password_manager_app.service;

import com.example.secure_password_manager_app.auth.AuthProvider;
import com.example.secure_password_manager_app.dto.user.PasswordChangeRequest;
import com.example.secure_password_manager_app.dto.user.UserProfileUpdateDto;
import com.example.secure_password_manager_app.dto.user.UserResponseDto;
import com.example.secure_password_manager_app.exception.ResourceNotFoundException;
import com.example.secure_password_manager_app.model.User;
import com.example.secure_password_manager_app.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Service class for managing user-related operations, including profile updates
 * and password changes for local users.
 */
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Fetches a user by their ID and maps it to a DTO.
     *
     * @param userId The ID of the user to fetch.
     * @return UserResponseDto containing non-sensitive user data.
     * @throws ResourceNotFoundException if the user is not found.
     */
    public UserResponseDto getUserById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
        return mapUserToUserResponseDto(user);
    }

    /**
     * Fetches a user by their username (email for local users) and maps it to a DTO.
     *
     * @param username The username (email) of the user.
     * @return UserResponseDto containing non-sensitive user data.
     * @throws UsernameNotFoundException if the user is not found.
     */
    public UserResponseDto getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        return mapUserToUserResponseDto(user);
    }

    /**
     * Updates a user's full name.
     * Note: Email changes are complex due to uniqueness constraints and OAuth2 linkage,
     * so they are not directly supported here.
     *
     * @param userId The ID of the user to update.
     * @param updateDto DTO containing updated profile information.
     * @return UserResponseDto of the updated user.
     * @throws ResourceNotFoundException if the user is not found.
     */
    public UserResponseDto updateProfile(Long userId, UserProfileUpdateDto updateDto) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        user.setFullName(updateDto.getFullName());
        // Potentially add logic for email change here, but it's often more complex due to uniqueness and verification
        // if (updateDto.getEmail() != null && !updateDto.getEmail().equals(user.getEmail())) {
        //     if (userRepository.existsByEmail(updateDto.getEmail())) {
        //         throw new IllegalArgumentException("Email already taken.");
        //     }
        //     user.setEmail(updateDto.getEmail());
        // }

        userRepository.save(user);
        return mapUserToUserResponseDto(user);
    }

    /**
     * Allows a local user to change their password.
     * This method explicitly checks if the user is a LOCAL provider and
     * validates the current password before updating.
     *
     * @param userId The ID of the user whose password is to be changed.
     * @param request PasswordChangeRequest containing current and new passwords.
     * @throws ResourceNotFoundException if the user is not found.
     * @throws IllegalArgumentException if the current password is incorrect or if the user is not a LOCAL provider.
     */
    public void changePassword(Long userId, PasswordChangeRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        // CRITICAL NOTE: Google users cannot change passwords via this endpoint.
        // They should manage their password through Google's account settings.
        if (user.getAuthProvider() != AuthProvider.LOCAL) {
            throw new IllegalArgumentException("Password change not allowed for " + user.getAuthProvider() + " accounts. Please manage your password through your provider settings.");
        }

        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Incorrect current password.");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    /**
     * Retrieves all users (for admin purposes).
     *
     * @return A list of UserResponseDto.
     */
    public List<UserResponseDto> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::mapUserToUserResponseDto)
                .collect(Collectors.toList());
    }

    /**
     * Deletes a user by ID.
     *
     * @param userId The ID of the user to delete.
     * @throws ResourceNotFoundException if the user is not found.
     */
    public void deleteUser(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new ResourceNotFoundException("User not found with id: " + userId);
        }
        userRepository.deleteById(userId);
    }

    /**
     * Helper method to map a User entity to a UserResponseDto,
     * ensuring sensitive information like password hash is not exposed.
     *
     * @param user The User entity.
     * @return A new UserResponseDto.
     */
    private UserResponseDto mapUserToUserResponseDto(User user) {
        return UserResponseDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .authProvider(user.getAuthProvider())
                .roles(user.getRoles())
                .createdAt(user.getCreatedAt())
                .lastLogin(user.getLastLogin())
                .build();
    }
}