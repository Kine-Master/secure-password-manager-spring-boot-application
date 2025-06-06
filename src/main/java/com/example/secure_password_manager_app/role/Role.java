package com.example.secure_password_manager_app.role;

import org.springframework.security.core.GrantedAuthority;

/**
 * Defines the roles a user can have in the application.
 * Implements GrantedAuthority for Spring Security integration.
 */
public enum Role implements GrantedAuthority {
    USER,
    ADMIN;

    /**
     * Returns the authority string for this role.
     * Spring Security expects roles to be prefixed with "ROLE_".
     * E.g., for 'USER' it returns 'ROLE_USER'.
     */
    @Override
    public String getAuthority() {
        return "ROLE_" + this.name();
    }
}