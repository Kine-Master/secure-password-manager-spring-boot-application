package com.example.secure_password_manager_app.dto.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for updating a user's profile information.
 * Note: Password changes are handled via a separate DTO and endpoint.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileUpdateDto {
    private String fullName;
    // Potentially allow updating email for local users, but needs careful handling for uniqueness
    // private String email;
}