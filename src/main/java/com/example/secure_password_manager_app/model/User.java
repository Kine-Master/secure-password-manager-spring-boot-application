package com.example.secure_password_manager_app.model;

import com.example.secure_password_manager_app.role.Role;
import com.example.secure_password_manager_app.auth.AuthProvider;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User; // NEW IMPORT: Required for OAuth2User interface

import lombok.*;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Setter
@Getter
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "`user`")
public class User implements UserDetails, OAuth2User { // MODIFIED: Implement OAuth2User interface

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username; // Used for email

    @Column(unique = true, nullable = false) // Email is crucial for uniqueness and OAuth2 lookup
    private String email;

    @Column(nullable = true) // Changed to nullable for OAuth users
    private String password;

    private String fullName;

    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;

    // OAuth2 provider fields
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private AuthProvider authProvider = AuthProvider.LOCAL;

    @Column(unique = true, nullable = true)
    private String googleId; // Stores Google's unique identifier

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<PasswordEntry> passwordEntries;

    // --- RBAC: Roles Field and Mapping ---
    @Builder.Default
    @ElementCollection(targetClass = Role.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    private Set<Role> roles = new HashSet<>();

    // --- OAuth2User Interface Implementations ---
    // NEW FIELD (NOT A DB COLUMN): To store OAuth2 attributes in memory during the request
    @Transient // This annotation ensures this field is NOT persisted to the database
    private Map<String, Object> attributes;

    /**
     * Returns the OAuth2 attributes of the user.
     * This method is part of the OAuth2User interface.
     * @return a Map of attributes provided by the OAuth2 provider.
     */
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    /**
     * Sets the OAuth2 attributes. This method is used by CustomOAuth2UserService
     * to pass the attributes received from the OAuth2 provider to this User entity.
     * @param attributes the map of attributes.
     */
    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    /**
     * Returns the unique identifier for the user from the OAuth2 provider's perspective.
     * This method is part of the OAuth2User interface.
     * For Google, this is typically the 'sub' claim (googleId).
     * @return the unique identifier.
     */
    @Override
    public String getName() {
        // For OAuth2 users, 'googleId' is the canonical name provided by Google.
        // For local users, this might be null if no OAuth2 attributes are set.
        // It's safe to return googleId here, as its primary use is for OAuth2 scenarios.
        return this.googleId;
    }

    // --- UserDetails Implementations (Existing Methods) ---
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}